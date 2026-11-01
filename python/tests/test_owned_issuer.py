"""An attestation issuer owned by a person: the verifier holds only a device key the owner authorizes."""

import pytest

from nodetide.core.claims import Attestation, ClaimDocument, verify_attestation, verify_revocation
from nodetide.core.crypto import KeyPair
from nodetide.core.identity import (
    AddDeviceEvent, GenesisEvent, Identity, IdentityType, RevokeDeviceEvent, Sigchain, approve, propose_governed,
)
from nodetide.core.storage import Storage
from nodetide.verifiers.issuer import IssuerNotReady, device_request, load_owned


def make_org(owner: Identity) -> Sigchain:
    genesis = GenesisEvent.create(
        KeyPair.generate(), identity_type=IdentityType.ORGANIZATION, name="My verifier",
        owners=[{"identity": owner.identity_hash, "weight": 100}],
    )
    approve(genesis, owner.identity_hash, owner.local_keypair, owner.sigchain.head_hash)
    return Sigchain(events=[genesis])


def authorize(org: Sigchain, owner: Identity, request: dict) -> None:
    event = propose_governed(
        AddDeviceEvent, org.head_hash, device_pubkey=request["device_pubkey"],
        device_encryption_pubkey=request["device_encryption_pubkey"], label=request["label"], capabilities=request["capabilities"],
    )
    approve(event, owner.identity_hash, owner.local_keypair, owner.sigchain.head_hash)
    org.append(event)


def test_owned_issuer_lifecycle():
    verifier_db = Storage.memory()
    owner = Identity.create(name="me")
    request = device_request(verifier_db, "My verifier")
    assert device_request(verifier_db, "My verifier")["device_pubkey"] == request["device_pubkey"]  # kept, not remade

    # no organization yet, then one that has not authorized the key: not ready, and nothing to sign with
    with pytest.raises(IssuerNotReady, match="ISSUER_ORG"):
        load_owned(verifier_db, "My verifier", None, None)
    org = make_org(owner)
    verifier_db.save_sigchain(owner.sigchain)
    verifier_db.save_sigchain(org)
    with pytest.raises(IssuerNotReady, match="not authorized"):
        load_owned(verifier_db, "My verifier", org.identity_hash, None)

    # the owner authorizes the key; the verifier now issues
    authorize(org, owner, request)
    verifier_db.save_sigchain(org)
    issuer = load_owned(verifier_db, "My verifier", org.identity_hash, None)
    assert issuer.identity_hash == org.identity_hash and issuer.name == "My verifier"
    assert issuer.identity.local_keypair is None  # no master key on the server

    holder = Identity.create(name="Alice")
    doc = ClaimDocument.create(holder.identity_hash, "email", "alice@example.com")
    holder.add_claim(doc.claim_id, doc.claim_type, doc.commitment)
    att = issuer.issue(holder.identity_hash, holder.sigchain.get_claim(doc.claim_id), holder.sigchain.head_hash, "email_code", "low")

    resolve = {owner.identity_hash: owner.sigchain}.get
    assert verify_attestation(att, holder.sigchain, org, resolve=resolve).ok
    assert not verify_attestation(att, holder.sigchain, org).ok  # a relying party must be able to look the owners up
    rev = issuer.revoke(att.id, "test")
    assert verify_revocation(rev, org, resolve=resolve).ok

    # the owner revokes the key: attestations signed from then on are refused
    revoke = propose_governed(RevokeDeviceEvent, org.head_hash, device_pubkey=request["device_pubkey"], reason="server lost")
    approve(revoke, owner.identity_hash, owner.local_keypair, owner.sigchain.head_hash)
    org.append(revoke)
    assert org.verify(resolve)[0]
    late = issuer.issue(holder.identity_hash, holder.sigchain.get_claim(doc.claim_id), holder.sigchain.head_hash, "email_code", "low")
    assert not verify_attestation(late, holder.sigchain, org, resolve=resolve).ok
    verifier_db.save_sigchain(org)
    with pytest.raises(IssuerNotReady):
        load_owned(verifier_db, "My verifier", org.identity_hash, None)
