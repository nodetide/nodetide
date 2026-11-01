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
from nodetide.core.identity import ClaimRecord, DeviceCapability, Identity, IdentityType, Sigchain
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
# The verifier holds only a signing device key. The organization it signs for belongs to its owners (see "Organization
# identities" in core/identity.py): they create it, authorize this key with an approved add_device event and can revoke
# it, all in their own wallet. Nothing here can change who owns the organization.

ISSUER_CAPABILITIES = [DeviceCapability.SIGN_IDENTITY.value]


class IssuerNotReady(Exception):
    """The owned issuer cannot sign yet: it has no organization or the organization has not authorized its key."""


def device_request(storage: Storage, name: str) -> dict[str, Any]:
    """The signing device's public data, which the owners authorize (made once, kept in storage)."""
    row = storage.get_issuer_device()
    if row is None:
        keypair = KeyPair.generate()
        storage.save_issuer_device(
            keypair.signing_key.to_hex(), keypair.verify_key.to_hex(), keypair.public_encryption_key.to_hex()
        )
        row = storage.get_issuer_device()
    assert row is not None
    return {
        "name": name,
        "device_pubkey": row["device_pubkey"],
        "device_encryption_pubkey": row["device_encryption_pubkey"],
        "label": "attestation signer",
        "capabilities": ISSUER_CAPABILITIES,
    }


def _fetch_chain(node_url: str, identity_hash: str) -> Sigchain:
    url = f"{node_url.rstrip('/')}/api/identities/{identity_hash}/sigchain"
    with urllib.request.urlopen(url, timeout=20) as response:  # noqa: S310 (operator-configured node address)
        return Sigchain.from_list(json.loads(response.read())["events"])


def load_owned(storage: Storage, name: str, org_hash: str | None, node_url: str | None) -> NodeIssuer:
    """The issuer for an organization its owners created. Raises IssuerNotReady until that organization lists our key.

    The organization's chain and its owners' chains are fetched from `node_url` (when given) and checked here, with
    the owners' chains as the resolver; what passes is kept in storage so the verifier can serve it.
    """
    request = device_request(storage, name)
    if not org_hash:
        raise IssuerNotReady("NODETIDE_ISSUER_ORG is not set: give the owners the device request and set it afterwards")
    chain = storage.get_sigchain(org_hash)
    if node_url:
        try:
            fetched = _fetch_chain(node_url, org_hash)
            owner_chains = {
                o["identity"]: _fetch_chain(node_url, o["identity"]) for o in (fetched.get_owners() or [])
            }
            if fetched.identity_hash != org_hash:
                raise IssuerNotReady("the node returned another chain than the organization asked for")
            ok, err = fetched.verify(owner_chains.get)
            if not ok:
                raise IssuerNotReady(f"the organization's chain does not verify: {err}")
            for owner_chain in owner_chains.values():
                storage.save_sigchain(owner_chain)
            storage.save_sigchain(fetched)
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
    device = next((d for d in chain.get_active_devices() if d.pubkey == request["device_pubkey"]), None)
    if device is None or DeviceCapability.SIGN_IDENTITY.value not in device.capabilities:
        raise IssuerNotReady("the organization's owners have not authorized this verifier's key yet")
    row = storage.get_issuer_device()
    assert row is not None
    return NodeIssuer(Identity(sigchain=chain, local_keypair=None), SigningKey.from_hex(row["device_signing_key"]))
