"""The node's own attestation issuer: an organization identity with one signing device."""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from nodetide.core.claims import (
    DEFAULT_ATTESTATION_LIFETIME,
    Attestation,
    AttestationRevocation,
)
from nodetide.core.crypto import KeyPair, SigningKey
from nodetide.core.identity import (
    AddDeviceEvent, ClaimRecord, DeviceCapability, GenesisEvent, Identity, IdentityType, Sigchain,
)
from nodetide.core.storage import Storage


class NodeIssuer:
    """Signs attestations on behalf of this node.

    The identity's master key is kept but never used for attestations; a
    separate device key with only `sign_identity` signs them, so it can be
    revoked and replaced without losing the issuer's identity.
    """

    def __init__(self, identity: Identity, device_key: SigningKey):
        self.identity = identity
        self.device_key = device_key

    @property
    def identity_hash(self) -> str:
        return self.identity.identity_hash or ""

    @property
    def name(self) -> str | None:
        genesis = self.identity.sigchain.genesis
        return genesis.name if genesis else None

    @classmethod
    def load_or_create(cls, storage: Storage, name: str) -> NodeIssuer:
        row = storage.get_node_issuer()
        if row is not None:
            chain = storage.get_sigchain(row["identity_hash"])
            if chain is None:
                raise RuntimeError("The node issuer's sigchain is missing from storage")
            keypair = KeyPair.from_dict({
                "signing_key": row["master_signing_key"],
                "encryption_key": row["master_encryption_key"],
            })
            return cls(Identity(sigchain=chain, local_keypair=keypair),
                       SigningKey.from_hex(row["device_signing_key"]))

        identity = Identity.create(identity_type=IdentityType.ORGANIZATION, name=name)
        device, _ = identity.add_device("attestation signer", capabilities=[DeviceCapability.SIGN_IDENTITY])
        storage.save_sigchain(identity.sigchain)
        assert identity.local_keypair is not None
        storage.save_node_issuer(
            identity_hash=identity.identity_hash or "",
            master_signing_key=identity.local_keypair.signing_key.to_hex(),
            master_encryption_key=identity.local_keypair.encryption_key.to_hex(),
            device_pubkey=device.verify_key.to_hex(),
            device_signing_key=device.signing_key.to_hex(),
        )
        return cls(identity, device.signing_key)

    def issue(
        self,
        subject: str,
        record: ClaimRecord,
        chain_head: str,
        method: str,
        assurance: str,
        evidence: dict[str, Any] | None = None,
        lifetime: int = DEFAULT_ATTESTATION_LIFETIME,
    ) -> Attestation:
        return Attestation.issue(
            self.identity_hash, self.device_key, subject, record, chain_head,
            method, assurance, evidence, lifetime,
        )

    def revoke(self, attestation_id: str, reason: str | None = None) -> AttestationRevocation:
        return AttestationRevocation.create(self.identity_hash, self.device_key, attestation_id, reason)


# --- An issuer owned by other identities ----------------------------------------------------------------------------
#
# The organization it signs for has its own key, held here, and runs itself with it: this key authorizes the signing
# device below, and a replacement later. Its OWNERS (other identities, with weights; see "Organization identities" in
# core/identity.py) are needed for two things only: the founding approval, and recovering the organization's key (or
# changing the owners) if this server's key is lost or taken. They approve in their own wallet; nothing here can change
# who the owners are.

ISSUER_CAPABILITIES = [DeviceCapability.SIGN_IDENTITY.value]


class IssuerNotReady(Exception):
    """The owned issuer cannot sign yet: its organization is not founded, or this server no longer holds its key."""


def parse_owners(text: str | None) -> list[dict[str, Any]]:
    """'<identity hash>[:weight],...' (weight defaults to 100) -> the owner list of a genesis."""
    owners = []
    for part in (text or "").replace("\n", ",").split(","):
        part = part.strip()
        if not part:
            continue
        identity, _, weight = part.partition(":")
        owners.append({"identity": identity.strip().lower(), "weight": int(weight) if weight.strip() else 100})
    if not owners:
        raise IssuerNotReady("NODETIDE_ISSUER_OWNERS is not set: name the identity (or identities) that own this issuer")
    return owners


def _owned_row(storage: Storage, name: str, owners_text: str | None) -> dict[str, Any]:
    """The keys and the (not yet approved) genesis of this issuer, made once and kept."""
    row = storage.get_owned_issuer()
    if row is None:
        owners = parse_owners(owners_text)
        master, device = KeyPair.generate(), KeyPair.generate()
        genesis = GenesisEvent.create(master, identity_type=IdentityType.ORGANIZATION, name=name, owners=owners)
        storage.save_owned_issuer(
            json.dumps(master.to_dict()), json.dumps(device.to_dict()), json.dumps(genesis.to_dict())
        )
        row = storage.get_owned_issuer()
    assert row is not None
    return row


def founding_request(storage: Storage, name: str, owners_text: str | None) -> dict[str, Any]:
    """What the owners approve to found the organization: the genesis, signed by the organization's own key."""
    row = _owned_row(storage, name, owners_text)
    genesis = json.loads(row["genesis_json"])
    return {"name": name, "genesis": genesis, "owners": genesis["owners"]}


def _http_json(url: str, body: dict[str, Any] | None = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 (operator-configured node address)
        return json.loads(response.read())


def _fetch_chain(node_url: str, identity_hash: str) -> Sigchain:
    return Sigchain.from_list(_http_json(f"{node_url.rstrip('/')}/api/identities/{identity_hash}/sigchain")["events"])


def load_owned(
    storage: Storage, name: str, org_hash: str | None, node_url: str | None, owners_text: str | None = None
) -> NodeIssuer:
    """The issuer for the organization its owners founded. Raises IssuerNotReady until that is the case.

    The organization's chain and its owners' chains are fetched from `node_url` (when given) and checked here; what
    passes is kept in storage so the verifier can serve it. If the chain does not yet list our signing device, the
    organization's own key adds it (an ordinary event, no owner needed) and the node is told.
    """
    row = _owned_row(storage, name, owners_text)
    if not org_hash:
        raise IssuerNotReady("NODETIDE_ISSUER_ORG is not set: the owners approve the founding request, then set it")
    master = KeyPair.from_dict(json.loads(row["master_keys"]))
    device = KeyPair.from_dict(json.loads(row["device_keys"]))
    chain = storage.get_sigchain(org_hash)
    if node_url:
        try:
            fetched = _fetch_chain(node_url, org_hash)
            owner_chains = {o["identity"]: _fetch_chain(node_url, o["identity"]) for o in (fetched.get_owners() or [])}
            if fetched.identity_hash != org_hash:
                raise IssuerNotReady("the node returned another chain than the organization asked for")
            ok, err = fetched.verify(owner_chains.get)
            if not ok:
                raise IssuerNotReady(f"the organization's chain does not verify: {err}")
            for owner_chain in owner_chains.values():
                storage.save_sigchain(owner_chain)
            chain = fetched
        except IssuerNotReady:
            raise
        except Exception as e:  # network trouble: fall back to what was stored before
            if chain is None:
                raise IssuerNotReady(f"cannot fetch the organization from {node_url}: {e}") from e
    if chain is None or not chain.is_organization:
        raise IssuerNotReady("the organization is not known here, or it has no owners")
    ok, err = chain.verify(storage.get_sigchain)
    if not ok:
        raise IssuerNotReady(f"the organization's chain does not verify: {err}")
    if chain.get_current_master_key() != master.verify_key.to_hex():
        raise IssuerNotReady(
            "the organization's key is no longer the one this server holds (its owners replaced it); "
            "this server needs the new key before it can act for the organization again"
        )

    device_pub = device.verify_key.to_hex()
    if not any(d.pubkey == device_pub and DeviceCapability.SIGN_IDENTITY.value in d.capabilities
               for d in chain.get_active_devices()):
        event = AddDeviceEvent.create(
            master, device, "attestation signer", chain.head_hash, [DeviceCapability.SIGN_IDENTITY]
        )
        chain.append(event)
        ok, err = chain.verify(storage.get_sigchain)
        if not ok:
            raise IssuerNotReady(f"cannot authorize the signing key: {err}")
        if node_url:
            try:
                _http_json(f"{node_url.rstrip('/')}/api/identities/{org_hash}/events", {"event": event.to_dict()})
            except Exception as e:
                raise IssuerNotReady(f"the node did not accept the signing key's authorization: {e}") from e
    storage.save_sigchain(chain)
    return NodeIssuer(Identity(sigchain=chain, local_keypair=master), device.signing_key)
