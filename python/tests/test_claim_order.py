"""set_claim_order: the holder's preferred claim of each type (their default email, say)."""

from __future__ import annotations

import copy

import pytest

from nodetide.core.claims import ClaimDocument
from nodetide.core.explorer_index import summarize_event
from nodetide.core.identity import DeviceCapability, Identity, SetClaimOrderEvent, Sigchain


def order_event(identity, signer, claim_type, order):
    """A set_claim_order built by hand (a content event), to try invalid ones."""
    chain = identity.sigchain
    return SetClaimOrderEvent.create(signer, chain.content_head, claim_type, order, seq=len(chain.content), control_ref=chain.head_hash)

D = DeviceCapability


def holder_with(*emails: str, phone: str | None = None) -> tuple[Identity, list[str], str | None]:
    identity = Identity.create(name="Maria")
    ids = []
    for address in emails:
        doc = ClaimDocument.create(identity.identity_hash, "email", address)
        identity.add_claim(doc.claim_id, "email", doc.commitment)
        ids.append(doc.claim_id)
    phone_id = None
    if phone:
        doc = ClaimDocument.create(identity.identity_hash, "phone", phone)
        identity.add_claim(doc.claim_id, "phone", doc.commitment)
        phone_id = doc.claim_id
    return identity, ids, phone_id


def test_without_an_order_claims_come_in_the_order_they_were_made():
    identity, ids, _ = holder_with("a@example.com", "b@example.com", "c@example.com")
    assert identity.sigchain.claim_order("email") == ids
    assert identity.sigchain.claim_order("phone") == []


def test_the_newest_order_wins_and_unlisted_claims_follow():
    identity, (a, b, c), _ = holder_with("a@example.com", "b@example.com", "c@example.com")
    identity.set_claim_order("email", [c, a])
    assert identity.sigchain.claim_order("email") == [c, a, b]
    identity.set_claim_order("email", [b])
    assert identity.sigchain.claim_order("email") == [b, a, c]
    assert identity.verify()[0]


def test_revoked_claims_drop_out_of_the_order():
    identity, (a, b, c), _ = holder_with("a@example.com", "b@example.com", "c@example.com")
    identity.set_claim_order("email", [c, b, a])
    identity.revoke_claim(c, "lost the mailbox")
    assert identity.sigchain.claim_order("email") == [b, a]  # the next one becomes the default


def test_orders_are_per_type():
    identity, (a, b), phone = holder_with("a@example.com", "b@example.com", phone="+359881234567")
    identity.set_claim_order("email", [b, a])
    assert identity.sigchain.claim_order("email") == [b, a] and identity.sigchain.claim_order("phone") == [phone]


def test_the_event_survives_serialisation_and_tampering_is_detected():
    identity, (a, b), _ = holder_with("a@example.com", "b@example.com")
    identity.set_claim_order("email", [b, a])
    restored = Sigchain.from_list(identity.sigchain.to_list())
    assert restored.verify()[0] and restored.claim_order("email") == [b, a]
    forged = copy.deepcopy(identity.sigchain.to_list())
    forged[-1]["order"] = [a, b]
    assert not Sigchain.from_list(forged).verify()[0]


@pytest.mark.parametrize("make", [
    lambda ids, phone: ("email", ["nope" * 5]),               # unknown claim
    lambda ids, phone: ("email", [ids[0], ids[0]]),            # listed twice
    lambda ids, phone: ("email", []),                          # nothing
    lambda ids, phone: ("email", [phone]),                     # a claim of another type
    lambda ids, phone: ("phone", [ids[0]]),                    # same, from the other side
    lambda ids, phone: ("email", [f"claim-id-{i:010d}" for i in range(33)]),  # too many
])
def test_invalid_orders_are_rejected(make):
    identity, ids, phone = holder_with("a@example.com", "b@example.com", phone="+359881234567")
    claim_type, order = make(ids, phone)
    event = order_event(identity, identity.local_keypair, claim_type, order)
    identity.sigchain.append(event)
    assert not identity.verify()[0]


def test_a_revoked_claim_cannot_be_ordered():
    identity, (a, b), _ = holder_with("a@example.com", "b@example.com")
    identity.revoke_claim(a)
    identity.sigchain.append(order_event(identity, identity.local_keypair, "email", [a, b]))
    assert not identity.verify()[0]


def test_only_the_master_or_a_claims_device_may_order_claims():
    identity, (a, b), _ = holder_with("a@example.com", "b@example.com")
    plain, _ = identity.add_device("laptop", capabilities=[D.AUTHENTICATE])
    manager, _ = identity.add_device("phone", capabilities=[D.MANAGE_CLAIMS])
    identity.sigchain.append(order_event(identity, plain.signing_key, "email", [b, a]))
    assert not identity.verify()[0]
    identity.sigchain.content.pop()
    identity.set_claim_order("email", [b, a], signer=manager.signing_key)
    assert identity.verify()[0] and identity.sigchain.claim_order("email") == [b, a]


def test_the_explorer_describes_it_without_values():
    identity, (a, b), _ = holder_with("a@example.com", "b@example.com")
    event = identity.set_claim_order("email", [b, a])
    assert summarize_event(event) == "Set the order of 2 email claims"
