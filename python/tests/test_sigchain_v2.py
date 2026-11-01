"""Sigchain v2: a control chain that commits to its content (see sigchain-v2.md)."""

import json

import pytest

from nodetide.core.claims import Attestation, ClaimDocument, verify_attestation
from nodetide.core.identity import (
    AddClaimEvent, CheckpointEvent, DeviceCapability as D, Identity, RevokeDeviceEvent, Sigchain, SigchainEvent,
)
from nodetide.core.merkle import merkle_root


def holder(*emails):
    ident = Identity.create(name="Alice")
    docs = []
    for email in emails:
        doc = ClaimDocument.create(ident.identity_hash, "email", email)
        ident.add_claim(doc.claim_id, doc.claim_type, doc.commitment)
        docs.append(doc)
    return ident, docs


def light_copy(ident: Identity) -> Sigchain:
    """What a light client gets: the control chain only."""
    return Sigchain.from_list(ident.sigchain.to_list(light=True))


def test_claims_live_in_the_content_track_and_do_not_touch_the_control_chain():
    ident, (doc,) = holder("a@example.com")
    chain = ident.sigchain
    assert [e.type.value for e in chain.events] == ["genesis"]
    assert [e.type.value for e in chain.content] == ["add_claim"]
    assert chain.content[0].seq == 0 and chain.content[0].prev is None and chain.content[0].control_ref == chain.head_hash
    assert ident.verify() == (True, None)
    # adding claims leaves the control head, and so every device check, exactly where it was
    head = chain.head_hash
    ident.add_claim("c" * 22, "email", "0" * 64)
    assert chain.head_hash == head


def test_every_control_event_commits_to_the_content_before_it():
    ident, _ = holder("a@example.com", "b@example.com")
    ident.add_device("laptop")
    commit = ident.sigchain.events[-1].content
    assert commit == {"count": 2, "root": merkle_root([e.event_hash() for e in ident.sigchain.content])}
    assert ident.verify() == (True, None)
    # a control event that forgets to commit makes the content before it uncommitted: invalid
    forged = Identity(sigchain=Sigchain.from_list(ident.sigchain.to_list()), local_keypair=ident.local_keypair)
    forged.add_claim("z" * 22, "email", "9" * 64)                       # content after the last commitment
    forged.sigchain.append(RevokeDeviceEvent.create(ident.local_keypair, "f" * 64, forged.sigchain.head_hash))
    ok, err = forged.verify()
    assert not ok and "commit" in err


@pytest.mark.parametrize("tamper,why", [
    (lambda c: c.update(root="00" * 32), "does not match the content"),
    (lambda c: c.update(count=7), "goes backwards|commits"),
    (lambda c: c.update(extra=1), "malformed"),
])
def test_bad_commitments_are_refused(tamper, why):
    ident, _ = holder("a@example.com")
    ident.add_device("laptop")
    ident.add_device("phone")
    chain = Sigchain.from_list(ident.sigchain.to_list())
    chain.events[1].content = dict(chain.events[1].content)
    tamper(chain.events[1].content)
    ok, err = chain.verify()
    assert not ok  # (the signature breaks too; the point is that the chain is refused)


def test_a_revoked_device_cannot_slip_content_into_the_past():
    """The commitment in revoke_device fixes the content that existed; later events under the old control_ref are out."""
    ident, _ = holder("a@example.com")
    phone, _ = ident.add_device("phone", capabilities=[D.MANAGE_CLAIMS])
    old_head = ident.sigchain.head_hash
    ident.revoke_device(phone.verify_key.to_hex(), "lost")

    # the thief signs a claim "as of" the moment before the revocation
    doc = ClaimDocument.create(ident.identity_hash, "email", "thief@example.com")
    evil = AddClaimEvent.create(
        phone.signing_key, ident.sigchain.content_head, doc.claim_id, doc.claim_type, doc.commitment,
        seq=len(ident.sigchain.content), control_ref=old_head,
    )
    ident.sigchain.append(evil)
    ok, err = ident.verify()
    assert not ok and "not committed by the control event that follows" in err


def test_content_signed_by_a_plain_device_is_refused_and_by_a_claims_device_accepted():
    ident, _ = holder("a@example.com")
    plain, _ = ident.add_device("plain", capabilities=[D.AUTHENTICATE])
    manager, _ = ident.add_device("manager", capabilities=[D.MANAGE_CLAIMS])
    ident.add_claim("m" * 22, "email", "1" * 64, signer=manager.signing_key)
    ident.checkpoint(signer=manager.signing_key)
    assert ident.verify() == (True, None)
    ident.add_claim("p" * 22, "email", "2" * 64, signer=plain.signing_key)
    assert not ident.verify()[0]
    ident.sigchain.content.pop()
    bad = CheckpointEvent.create(plain.signing_key, ident.sigchain.head_hash, ident.sigchain.content_commitment())
    ident.sigchain.append(bad)
    assert not ident.verify()[0]  # a plain device cannot checkpoint either


# --- light verification ----------------------------------------------------------------------------------


def test_a_light_chain_verifies_without_the_content_and_knows_it_is_partial():
    ident, (doc,) = holder("a@example.com")
    ident.add_device("laptop")  # commits the claim
    light = light_copy(ident)
    assert light.content == [] and light.is_partial
    assert light.verify() == (True, None)             # the control chain checks out on its own
    assert light.get_claim(doc.claim_id) is None       # and nothing about content is assumed
    assert not ident.sigchain.is_partial
    # the identity hash and head are the same on both
    assert light.identity_hash == ident.identity_hash and light.head_hash == ident.sigchain.head_hash


def test_a_claim_is_proven_to_a_light_chain_with_a_merkle_path():
    ident, docs = holder("a@example.com", "b@example.com", "c@example.com")
    ident.add_device("laptop")
    for seq, doc in enumerate(docs):
        light = light_copy(ident)
        proof = ident.sigchain.content_proof(seq)
        err = light.attach_content(SigchainEvent.from_dict(proof["event"]), proof["proof"])
        assert err is None, err
        assert light.get_claim(doc.claim_id).commitment == doc.commitment
        assert len(light.sparse) == 1                  # only that one claim is known


def test_proofs_that_do_not_fit_are_refused():
    ident, docs = holder("a@example.com", "b@example.com")
    ident.add_device("laptop")
    good = ident.sigchain.content_proof(0)
    other = ident.sigchain.content_proof(1)
    light = light_copy(ident)
    event = SigchainEvent.from_dict(good["event"])
    assert "Merkle proof" in light.attach_content(event, other["proof"])          # another leaf's path
    forged = SigchainEvent.from_dict({**good["event"], "commitment": "0" * 64})
    assert light.attach_content(forged, good["proof"]) is not None                # a changed event
    assert light.attach_content(event, []) is not None                            # no path at all


def test_content_the_control_chain_does_not_commit_yet_cannot_be_relied_on_by_a_light_client():
    ident, docs = holder("a@example.com")
    light = light_copy(ident)
    # no control event after the claim: it is only the tail
    with pytest.raises(ValueError):
        ident.sigchain.content_proof(0)
    assert "not committed" in light.attach_content(ident.sigchain.content[0], [])
    ident.checkpoint()                                     # now it is
    light = light_copy(ident)
    proof = ident.sigchain.content_proof(0)
    assert light.attach_content(SigchainEvent.from_dict(proof["event"]), proof["proof"]) is None


def test_revocation_is_seen_by_a_light_chain_because_it_is_a_control_event():
    ident, (doc,) = holder("a@example.com")
    ident.checkpoint()
    ident.revoke_claim(doc.claim_id, "gone")
    light = light_copy(ident)
    proof = ident.sigchain.content_proof(0)
    assert light.attach_content(SigchainEvent.from_dict(proof["event"]), proof["proof"]) is None
    assert light.get_claim(doc.claim_id).status() == "revoked"
    assert doc.claim_id in light.revoked_claim_ids()


def test_behind_is_not_wrong():
    ident, (doc,) = holder("a@example.com")
    ident.checkpoint()
    old = light_copy(ident)                                  # what a light client saw earlier
    ident.add_device("laptop")                               # control moves on
    ident.add_claim("n" * 22, "email", "3" * 64)             # content under the NEW control head
    ident.checkpoint()
    newer = ident.sigchain.content_proof(1)
    err = old.attach_content(SigchainEvent.from_dict(newer["event"]), newer["proof"])
    assert err.startswith("behind:")                         # it names a control event this chain has not seen yet

    # and an attestation made against the newer head says the same, before anything else
    issuer = Identity.create(name="V", identity_type=__import__("nodetide.core.identity", fromlist=["IdentityType"]).IdentityType.ORGANIZATION)
    dev, _ = issuer.add_device("signer", capabilities=[D.SIGN_IDENTITY])
    record = ident.sigchain.get_claim(doc.claim_id)
    att = Attestation.issue(issuer.identity_hash, dev, ident.identity_hash, record, ident.sigchain.head_hash, "email_code", "low")
    check = verify_attestation(att, old, issuer.sigchain)
    assert check.code == "unknown_chain_head"
    assert verify_attestation(att, ident.sigchain, issuer.sigchain).ok


def test_an_attestation_is_checked_with_the_control_chain_and_one_proof():
    ident, docs = holder("a@example.com", "b@example.com")
    doc = docs[0]
    ident.checkpoint()
    issuer = Identity.create(name="V", identity_type=__import__("nodetide.core.identity", fromlist=["IdentityType"]).IdentityType.ORGANIZATION)
    dev, _ = issuer.add_device("signer", capabilities=[D.SIGN_IDENTITY])
    record = ident.sigchain.get_claim(doc.claim_id)
    att = Attestation.issue(issuer.identity_hash, dev, ident.identity_hash, record, ident.sigchain.head_hash, "email_code", "low")

    light = light_copy(ident)
    assert verify_attestation(att, light, issuer.sigchain).code == "unknown_claim"   # without the proof nothing is claimed
    proof = ident.sigchain.content_proof(0)
    assert light.attach_content(SigchainEvent.from_dict(proof["event"]), proof["proof"]) is None
    assert verify_attestation(att, light, issuer.sigchain).ok
    assert len(json.dumps(light.to_list())) < len(json.dumps(ident.sigchain.to_list())) + 1  # never more than the full chain


def test_serialization_round_trip_keeps_both_tracks():
    ident, _ = holder("a@example.com")
    ident.add_device("laptop")
    again = Sigchain.from_json(ident.sigchain.to_json())
    assert again.head_hash == ident.sigchain.head_hash and [e.event_hash() for e in again.content] == [e.event_hash() for e in ident.sigchain.content]
    assert again.verify() == (True, None)
