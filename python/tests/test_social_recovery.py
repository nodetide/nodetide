"""Social recovery: trustees' signatures are checked, on the chain and through the node."""

from nodetide.core.crypto import KeyPair
from nodetide.core.identity import (
    GenesisEvent, Identity, IdentityType, SocialRecoveryEvent, Sigchain, approve, propose_governed, RotateMasterEvent,
    sign_recovery,
)


class World:
    def __init__(self):
        self.chains = {}

    def person(self, name):
        i = Identity.create(name=name)
        self.chains[i.identity_hash] = i.sigchain
        return i

    def resolve(self, h):
        return self.chains.get(h)


def recover(victim: Identity, trustees: list[Identity], new: KeyPair, prev=None, tamper=None):
    prev = prev or victim.sigchain.head_hash
    sigs = [
        sign_recovery(t.identity_hash, t.local_keypair, t.sigchain.head_hash, victim.identity_hash, prev,
                      new.verify_key.to_hex(), new.public_encryption_key.to_hex())
        for t in trustees
    ]
    ev = SocialRecoveryEvent(
        type=None, timestamp=1, prev=prev, signature="", signed_by=new.verify_key.to_hex(),
        new_pubkey=new.verify_key.to_hex(), new_encryption_pubkey=new.public_encryption_key.to_hex(),
        recovery_signatures=sigs,
    )
    if tamper:
        tamper(ev)
    import json
    ev.signature = new.sign_hex(json.dumps(ev.signable_dict(), sort_keys=True, separators=(",", ":")).encode())
    return ev


def setup(threshold=2):
    w = World()
    me, a, b, c = (w.person(n) for n in ("me", "a", "b", "c"))
    me.set_recovery([a.identity_hash, b.identity_hash, c.identity_hash], threshold)
    return w, me, a, b, c


def test_enough_trustees_restore_the_identity():
    w, me, a, b, c = setup()
    new = KeyPair.generate()
    me.sigchain.append(recover(me, [a, c], new))
    assert me.sigchain.verify(w.resolve, check_current=True) == (True, None)
    assert me.sigchain.get_current_master_key() == new.verify_key.to_hex()


def test_too_few_trustees_fail():
    w, me, a, b, c = setup()
    me.sigchain.append(recover(me, [a], KeyPair.generate()))
    ok, err = me.sigchain.verify(w.resolve)
    assert not ok and "1 of 2" in err


def test_strangers_and_duplicates_do_not_count():
    w, me, a, b, c = setup()
    stranger = w.person("stranger")
    me.sigchain.append(recover(me, [a, stranger], KeyPair.generate()))
    assert "not a trustee" in me.sigchain.verify(w.resolve)[1]
    me.sigchain.events.pop()
    me.sigchain.append(recover(me, [a, a], KeyPair.generate()))
    assert "twice" in me.sigchain.verify(w.resolve)[1]


def test_no_recovery_set_up_means_no_recovery():
    w = World()
    me, a = w.person("me"), w.person("a")
    me.sigchain.append(recover(me, [a], KeyPair.generate()))
    assert "no recovery was set up" in me.sigchain.verify(w.resolve)[1]


def test_signatures_are_bound_to_the_new_key_and_the_chain_head():
    w, me, a, b, c = setup()
    new = KeyPair.generate()
    ev = recover(me, [a, b], new)
    other = KeyPair.generate()
    ev.new_pubkey = other.verify_key.to_hex()  # trustees agreed to a different key
    ev.signed_by = ev.new_pubkey
    import json
    ev.signature = other.sign_hex(json.dumps(ev.signable_dict(), sort_keys=True, separators=(",", ":")).encode())
    me.sigchain.append(ev)
    assert "invalid" in me.sigchain.verify(w.resolve)[1]
    me.sigchain.events.pop()
    me.sigchain.append(recover(me, [a, b], new, prev="00" * 32))  # signatures made for another head
    assert not me.sigchain.verify(w.resolve)[0]


def test_event_must_be_signed_by_the_new_key():
    w, me, a, b, c = setup()
    new = KeyPair.generate()
    ev = recover(me, [a, b], new)
    ev.signed_by = me.local_keypair.verify_key.to_hex()
    import json
    ev.signature = me.local_keypair.sign_hex(json.dumps(ev.signable_dict(), sort_keys=True, separators=(",", ":")).encode())
    me.sigchain.append(ev)
    assert "new key" in me.sigchain.verify(w.resolve)[1]


def test_recovery_setup_rules():
    w = World()
    me, a, b = w.person("me"), w.person("a"), w.person("b")
    for trustees, threshold in [([a.identity_hash, b.identity_hash], 3), ([a.identity_hash], 0), ([a.identity_hash, a.identity_hash], 1), ([me.identity_hash], 1)]:
        chain = Sigchain(events=list(me.sigchain.events))
        ident = Identity(sigchain=chain, local_keypair=me.local_keypair)
        ident.set_recovery(trustees, threshold)
        assert not chain.verify(w.resolve)[0], (trustees, threshold)


def test_a_trustee_who_rotated_still_vouches_but_the_old_key_cannot_sign_new_recoveries():
    w, me, a, b, c = setup()
    new = KeyPair.generate()
    ev = recover(me, [a, b], new)
    a.rotate_master()  # after signing
    me.sigchain.append(ev)
    assert me.sigchain.verify(w.resolve)[0]                       # history holds
    ok, err = me.sigchain.verify(w.resolve, check_current=True)   # a node refuses a signature from a replaced key
    assert not ok and "since replaced" in err


def test_recovered_owner_keeps_an_organization_alive():
    w, me, a, b, c = setup()
    key = KeyPair.generate()
    genesis = GenesisEvent.create(key, identity_type=IdentityType.ORGANIZATION, owners=[{"identity": me.identity_hash, "weight": 100}])
    approve(genesis, me.identity_hash, me.local_keypair, me.sigchain.head_hash)
    org = Sigchain(events=[genesis])
    w.chains[org.identity_hash] = org
    assert org.verify(w.resolve)[0]

    new = KeyPair.generate()  # the owner loses their key and is restored by two trustees
    me.sigchain.append(recover(me, [a, b], new))
    assert me.sigchain.verify(w.resolve, check_current=True)[0]

    ev = propose_governed(RotateMasterEvent, org.head_hash, new_pubkey=KeyPair.generate().verify_key.to_hex(), new_encryption_pubkey="00" * 32)
    approve(ev, me.identity_hash, new, me.sigchain.head_hash)
    org.append(ev)
    assert org.verify(w.resolve, check_current=True) == (True, None)
