"""Organization identities: owners with weights, governed key changes, owners that recover their own keys."""

import json

import pytest

from nodetide.core.crypto import KeyPair
from nodetide.core.identity import (
    AddDeviceEvent, GenesisEvent, Identity, IdentityType, RevokeDeviceEvent, RotateMasterEvent, SetOwnersEvent,
    Sigchain, approve, propose_governed,
)


class World:
    """A little network of identities: resolve() is what a node's storage does."""

    def __init__(self):
        self.chains: dict[str, Sigchain] = {}

    def person(self, name="p") -> Identity:
        ident = Identity.create(name=name)
        self.chains[ident.identity_hash] = ident.sigchain
        return ident

    def resolve(self, h):
        return self.chains.get(h)

    def org(self, owners: list[tuple[Identity, int]], org_key: KeyPair | None = None, governance: str | None = None):
        key = org_key or KeyPair.generate()
        decl = [{"identity": o.identity_hash, "weight": w} for o, w in owners]
        genesis = GenesisEvent.create(
            key, identity_type=IdentityType.ORGANIZATION, name="org", owners=decl, governance=governance
        )
        for o, _ in owners:
            approve(genesis, o.identity_hash, o.local_keypair, o.sigchain.head_hash)
        chain = Sigchain(events=[genesis])
        self.chains[chain.identity_hash] = chain
        return chain, key


def sign(event, *owners: Identity):
    for o in owners:
        approve(event, o.identity_hash, o.local_keypair, o.sigchain.head_hash)
    return event


def recover_key(chain, new: KeyPair, *owners):
    """The owners restore the organization's key: a governed rotate_master."""
    ev = propose_governed(
        RotateMasterEvent, chain.head_hash, new_pubkey=new.verify_key.to_hex(),
        new_encryption_pubkey=new.public_encryption_key.to_hex(),
    )
    return sign(ev, *owners)


def org_adds_device(chain, org_key: KeyPair, device: KeyPair):
    """An ordinary add_device signed by the organization's own key: no owner involved."""
    ev = AddDeviceEvent.create(org_key, device, "verifier", chain.head_hash, None)
    return ev


def test_single_owner_org_runs_itself_and_needs_its_owner_only_for_key_recovery():
    w = World()
    me = w.person("me")
    chain, key = w.org([(me, 100)])
    assert chain.verify(w.resolve) == (True, None)
    assert chain.is_organization
    # devices are the organization's own business: its key signs them, no owner involved
    chain.append(org_adds_device(chain, key, KeyPair.generate()))
    assert chain.verify(w.resolve, check_current=True) == (True, None)
    assert len(chain.get_active_devices()) == 2  # org key + new device
    # and it can rotate its own key
    chain.append(RotateMasterEvent.create(key, KeyPair.generate(), chain.head_hash))
    assert chain.verify(w.resolve)[0]
    # recovering a lost key is the owners' job
    chain.append(recover_key(chain, KeyPair.generate(), me))
    assert chain.verify(w.resolve, check_current=True)[0]


def test_unapproved_or_unsigned_events_are_rejected():
    w = World()
    me = w.person()
    chain, _ = w.org([(me, 100)])
    chain.append(recover_key(chain, KeyPair.generate()))  # no approvals
    ok, err = chain.verify(w.resolve)
    assert not ok and "not over half" in err


def test_over_half_rule_is_strict():
    w = World()
    a, b, c = w.person("a"), w.person("b"), w.person("c")
    chain, _ = w.org([(a, 45), (b, 30), (c, 25)])
    assert chain.verify(w.resolve)[0]
    dev = KeyPair.generate()

    for signers, expected in [((a,), False), ((b,), False), ((c,), False), ((b, c), True), ((a, c), True), ((a, b), True)]:
        trial = Sigchain(events=list(chain.events))
        trial.append(recover_key(trial, dev, *signers))
        assert trial.verify(w.resolve)[0] is expected, [s.sigchain.genesis.name for s in signers]

    # exactly half does not pass
    w2 = World()
    x, y = w2.person(), w2.person()
    chain2, _ = w2.org([(x, 50), (y, 50)])
    chain2.append(recover_key(chain2, dev, x))
    assert not chain2.verify(w2.resolve)[0]


def test_genesis_needs_every_founding_owner():
    w = World()
    a, b = w.person(), w.person()
    key = KeyPair.generate()
    genesis = GenesisEvent.create(
        key, identity_type=IdentityType.ORGANIZATION, owners=[{"identity": a.identity_hash, "weight": 60}, {"identity": b.identity_hash, "weight": 40}],
    )
    approve(genesis, a.identity_hash, a.local_keypair, a.sigchain.head_hash)  # b has not agreed
    ok, err = Sigchain(events=[genesis]).verify(w.resolve)
    assert not ok and "every founding owner" in err


def test_owner_list_rules():
    w = World()
    a = w.person()
    other_org, _ = w.org([(a, 1)])
    for owners, why in [
        ([], "between 1"),
        ([{"identity": a.identity_hash, "weight": 0}], "weight"),
        ([{"identity": a.identity_hash, "weight": 1.5}], "weight"),
        ([{"identity": a.identity_hash, "weight": True}], "weight"),
        ([{"identity": a.identity_hash, "weight": 1}, {"identity": a.identity_hash, "weight": 1}], "twice"),
        ([{"identity": "nobody", "weight": 1}], "unknown"),
        ([{"identity": other_org.identity_hash, "weight": 1}], "personal"),
    ]:
        genesis = GenesisEvent.create(KeyPair.generate(), identity_type=IdentityType.ORGANIZATION, owners=owners)
        ok, err = Sigchain(events=[genesis]).verify(w.resolve)
        assert not ok and why in err, (owners, err)


def test_organization_cannot_be_verified_without_owner_chains():
    w = World()
    me = w.person()
    chain, _ = w.org([(me, 100)])
    assert not chain.verify()[0]


def test_org_key_alone_cannot_change_owners_or_set_recovery():
    w = World()
    me, other = w.person(), w.person()
    chain, key = w.org([(me, 100)])
    ev = SetOwnersEvent(type=None, timestamp=1, prev=chain.head_hash, signature="", signed_by=key.verify_key.to_hex(),
                        owners=[{"identity": other.identity_hash, "weight": 100}])
    ev.signature = key.sign_hex(json.dumps(ev.signable_dict(), sort_keys=True, separators=(",", ":")).encode())
    trial = Sigchain(events=list(chain.events) + [ev])
    ok, err = trial.verify(w.resolve)
    assert not ok and "decided by its owners" in err

    trial = Sigchain(events=list(chain.events))
    Identity(sigchain=trial, local_keypair=key).set_recovery([me.identity_hash], 1)
    ok, err = trial.verify(w.resolve)
    assert not ok and "decided by its owners" in err


def test_owners_cannot_decide_devices():
    w = World()
    me = w.person()
    chain, _ = w.org([(me, 100)])
    dev = KeyPair.generate()
    ev = propose_governed(AddDeviceEvent, chain.head_hash, device_pubkey=dev.verify_key.to_hex(),
                          device_encryption_pubkey=dev.public_encryption_key.to_hex(), label="x", capabilities=[])
    chain.append(sign(ev, me))
    ok, err = chain.verify(w.resolve)
    assert not ok and "cannot be decided by owners" in err


def test_rotate_key_by_owners_and_old_key_loses_power():
    w = World()
    me = w.person()
    chain, old = w.org([(me, 100)])
    new = KeyPair.generate()
    ev = propose_governed(RotateMasterEvent, chain.head_hash, new_pubkey=new.verify_key.to_hex(), new_encryption_pubkey=new.public_encryption_key.to_hex())
    chain.append(sign(ev, me))
    assert chain.verify(w.resolve)[0]
    assert chain.get_current_master_key() == new.verify_key.to_hex()


def test_old_org_key_loses_power_after_owner_recovery():
    w = World()
    me = w.person()
    chain, old = w.org([(me, 100)])
    new = KeyPair.generate()
    chain.append(recover_key(chain, new, me))
    chain.append(org_adds_device(chain, old, KeyPair.generate()))  # the lost/stolen key tries again
    ok, err = chain.verify(w.resolve)
    assert not ok and "master" in err
    chain.events.pop()
    chain.append(org_adds_device(chain, new, KeyPair.generate()))
    assert chain.verify(w.resolve)[0]


def test_org_revokes_its_own_device():
    w = World()
    me = w.person()
    chain, key = w.org([(me, 100)])
    dev = KeyPair.generate()
    chain.append(org_adds_device(chain, key, dev))
    chain.append(RevokeDeviceEvent.create(key, dev.verify_key.to_hex(), chain.head_hash, "lost"))
    assert chain.verify(w.resolve)[0]
    assert dev.verify_key.to_hex() not in [d.pubkey for d in chain.get_active_devices()]


def test_changing_owners_uses_the_old_owners_and_the_old_weights():
    w = World()
    a, b = w.person("a"), w.person("b")
    chain, _ = w.org([(a, 100)])
    # b cannot vote itself in
    ev = propose_governed(SetOwnersEvent, chain.head_hash, owners=[{"identity": b.identity_hash, "weight": 100}])
    trial = Sigchain(events=list(chain.events) + [sign(ev, b)])
    assert not trial.verify(w.resolve)[0]
    # a hands over to a and b
    ev = propose_governed(SetOwnersEvent, chain.head_hash, owners=[{"identity": a.identity_hash, "weight": 60}, {"identity": b.identity_hash, "weight": 40}])
    chain.append(sign(ev, a))
    assert chain.verify(w.resolve)[0]
    assert [o["weight"] for o in chain.get_owners()] == [60, 40]
    # a (60 of 100) now suffices alone, b (40) does not
    c1 = Sigchain(events=list(chain.events)); c1.append(recover_key(c1, KeyPair.generate(), a))
    c2 = Sigchain(events=list(chain.events)); c2.append(recover_key(c2, KeyPair.generate(), b))
    assert c1.verify(w.resolve)[0] and not c2.verify(w.resolve)[0]


def test_approval_cannot_be_moved_to_another_event_or_org():
    w = World()
    me = w.person()
    chain, _ = w.org([(me, 100)])
    good = recover_key(chain, KeyPair.generate(), me)
    evil_key = KeyPair.generate()
    evil = propose_governed(
        RotateMasterEvent, chain.head_hash, new_pubkey=evil_key.verify_key.to_hex(),
        new_encryption_pubkey=evil_key.public_encryption_key.to_hex(),
    )
    evil.approvals = good.approvals
    trial = Sigchain(events=list(chain.events) + [evil])
    ok, err = trial.verify(w.resolve)
    assert not ok and "signature invalid" in err


def test_owner_who_rotates_their_key_keeps_old_events_valid_but_cannot_sign_with_the_old_key():
    w = World()
    me = w.person()
    chain, _ = w.org([(me, 100)])
    chain.append(recover_key(chain, KeyPair.generate(), me))  # signed with the key at the time
    stale = recover_key(chain, KeyPair.generate(), me)  # prepared with the old key, not yet submitted
    old_state_chain = Sigchain(events=list(chain.events) + [stale])

    me.rotate_master()
    assert chain.verify(w.resolve)[0]                                # history stays valid after the owner rotates
    assert old_state_chain.verify(w.resolve)[0]                      # as of the state it names, the key was right
    ok, err = old_state_chain.verify(w.resolve, check_current=True)  # a node refuses it as a NEW event
    assert not ok and "since replaced" in err

    fresh = recover_key(chain, KeyPair.generate(), me)  # signed again after the rotation
    chain.append(fresh)
    assert chain.verify(w.resolve, check_current=True)[0]


def test_owner_recovered_by_trustees_can_still_act_for_the_org():
    """The point of owning through an identity: losing the owner's key is the owner's recovery problem, not the org's."""
    from nodetide.core.identity import SocialRecoveryEvent

    w = World()
    me = w.person()
    chain, _ = w.org([(me, 100)])
    # me loses their key; a recovery event (trustee signatures are checked in the next step of the work) installs a new one
    new = KeyPair.generate()
    rec = SocialRecoveryEvent(
        type=None, timestamp=1, prev=me.sigchain.head_hash, signature="", signed_by=new.verify_key.to_hex(),
        new_pubkey=new.verify_key.to_hex(), new_encryption_pubkey=new.public_encryption_key.to_hex(), recovery_signatures=[],
    )
    me.sigchain.append(rec)
    ev = propose_governed(RotateMasterEvent, chain.head_hash, new_pubkey=KeyPair.generate().verify_key.to_hex(), new_encryption_pubkey="00" * 32)
    approve(ev, me.identity_hash, new, me.sigchain.head_hash)
    chain.append(ev)
    assert chain.verify(w.resolve, check_current=True)[0]
    # and the lost key no longer works for new events
    ev2 = propose_governed(RotateMasterEvent, chain.head_hash, new_pubkey=KeyPair.generate().verify_key.to_hex(), new_encryption_pubkey="00" * 32)
    approve(ev2, me.identity_hash, me.local_keypair, rec.prev)  # old key at the old state
    chain.append(ev2)
    assert not chain.verify(w.resolve, check_current=True)[0]


def test_ordinary_identities_are_unchanged():
    ident = Identity.create(name="plain")
    d = ident.sigchain.genesis.to_dict()
    assert "owners" not in d and "approvals" not in d
    ident.add_device("x")
    assert ident.verify() == (True, None)
    ev = propose_governed(SetOwnersEvent, ident.sigchain.head_hash, owners=[{"identity": "x", "weight": 1}])
    ident.sigchain.append(ev)
    assert not ident.verify()[0]


def test_roundtrip_serialization_keeps_approvals():
    w = World()
    me = w.person()
    chain, _ = w.org([(me, 100)])
    chain.append(recover_key(chain, KeyPair.generate(), me))
    again = Sigchain.from_list(chain.to_list())
    assert again.head_hash == chain.head_hash
    assert again.verify(w.resolve)[0]


def governed_device(chain, device: KeyPair, *owners):
    ev = propose_governed(
        AddDeviceEvent, chain.head_hash, device_pubkey=device.verify_key.to_hex(),
        device_encryption_pubkey=device.public_encryption_key.to_hex(), label="d", capabilities=["manage_claims"],
    )
    return sign(ev, *owners)


def test_managed_org_devices_need_the_owners_and_not_the_org_key():
    w = World()
    a, b, c = w.person("a"), w.person("b"), w.person("c")
    chain, key = w.org([(a, 45), (b, 30), (c, 25)], governance="managed")
    assert chain.verify(w.resolve)[0]
    dev = KeyPair.generate()

    # the organization's own key may not add a device, revoke one or rotate itself
    for forged in (
        org_adds_device(chain, key, dev),
        RevokeDeviceEvent.create(key, dev.verify_key.to_hex(), chain.head_hash, "x"),
        RotateMasterEvent.create(key, KeyPair.generate(), chain.head_hash),
    ):
        trial = Sigchain(events=list(chain.events) + [forged])
        ok, err = trial.verify(w.resolve)
        assert not ok and "decided by its owners" in err, err

    # owners: over half of the weight decides
    for signers, expected in [((a,), False), ((b, c), True), ((a, c), True)]:
        trial = Sigchain(events=list(chain.events))
        trial.append(governed_device(trial, dev, *signers))
        assert trial.verify(w.resolve)[0] is expected

    chain.append(governed_device(chain, dev, a, b))
    assert dev.verify_key.to_hex() in [d.pubkey for d in chain.get_active_devices()]
    rev = propose_governed(RevokeDeviceEvent, chain.head_hash, device_pubkey=dev.verify_key.to_hex(), reason="gone")
    chain.append(sign(rev, a, c))
    assert chain.verify(w.resolve)[0]
    assert dev.verify_key.to_hex() not in [d.pubkey for d in chain.get_active_devices()]


def test_managed_org_still_keeps_claims_with_its_own_key():
    from nodetide.core.claims import ClaimDocument
    from nodetide.core.identity import AddClaimEvent

    w = World()
    me = w.person()
    chain, key = w.org([(me, 100)], governance="managed")
    doc = ClaimDocument.create(chain.identity_hash, "email", "ops@example.org")
    chain.append(AddClaimEvent.create(key, chain.head_hash, doc.claim_id, doc.claim_type, doc.commitment))
    assert chain.verify(w.resolve)[0]


def test_governance_value_and_where_it_may_appear():
    w = World()
    me = w.person()
    chain, _ = w.org([(me, 100)], governance="sideways")
    ok, err = chain.verify(w.resolve)
    assert not ok and "governance" in err
    plain = GenesisEvent.create(KeyPair.generate(), governance="self")
    ok, err = Sigchain(events=[plain]).verify(w.resolve)
    assert not ok and "without owners" in err


def test_self_mode_is_the_default_and_leaves_old_hashes_alone():
    w = World()
    me = w.person()
    chain, _ = w.org([(me, 100)])
    assert "governance" not in chain.genesis.to_dict()
    chain2, _ = w.org([(me, 100)], governance="self")
    assert chain2.genesis.to_dict()["governance"] == "self" and chain2.verify(w.resolve)[0]
    dev = KeyPair.generate()
    chain2.append(governed_device(chain2, dev, me))  # still the owners' business only in managed mode
    assert not chain2.verify(w.resolve)[0]
