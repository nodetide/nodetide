"""Replacing the key of an organization whose verifier installation is compromised (owners decide; the old install is cut off)."""

import asyncio
import time

import pytest

from nodetide.core.claims import ClaimDocument, verify_attestation
from nodetide.core.identity import (
    GenesisEvent, Identity, RevokeDeviceEvent, RotateMasterEvent, Sigchain, SigchainEvent, approve, propose_governed,
)
from nodetide.core.storage import Storage
from nodetide.verifiers.issuer import IssuerNotReady, discover_org, founding_request, load_owned

T = int(time.time()) - 3600           # the owners judge the compromise began an hour ago


def found(request, owner) -> Sigchain:
    genesis = SigchainEvent.from_dict(request["genesis"])
    approve(genesis, owner.identity_hash, owner.local_keypair, owner.sigchain.head_hash)
    return Sigchain(events=[genesis])


class World:
    """An organization run by installation A, a holder with a claim, and the owner."""

    def __init__(self):
        self.owner = Identity.create(name="me")
        self.db_a = Storage.memory()
        request = founding_request(self.db_a, "V", self.owner.identity_hash)
        self.org = found(request, self.owner)
        self.db_a.save_sigchain(self.owner.sigchain)
        self.db_a.save_sigchain(self.org)
        self.a = load_owned(self.db_a, "V", self.org.identity_hash, None, self.owner.identity_hash)
        self.chain = self.a.identity.sigchain            # the organization's chain, with A's device on it
        self.org_hash = self.org.identity_hash
        self.resolve = {self.owner.identity_hash: self.owner.sigchain}.get

        self.holder = Identity.create(name="Alice")
        doc = ClaimDocument.create(self.holder.identity_hash, "email", "alice@example.com")
        self.holder.add_claim(doc.claim_id, doc.claim_type, doc.commitment)
        self.holder.checkpoint()
        self.record = self.holder.sigchain.get_claim(doc.claim_id)

    def attest(self, installation, at):
        return installation.issue(self.holder.identity_hash, self.record, self.holder.sigchain.head_hash,
                                  "email_code", "low", lifetime=3 * 365 * 86400)

    def attest_at(self, installation, at):
        from nodetide.core.claims import Attestation
        return Attestation.issue(installation.identity_hash, installation.device_key, self.holder.identity_hash, self.record,
                                 self.holder.sigchain.head_hash, "email_code", "low", now=at)

    def fresh_installation(self):
        """A clean install that asks to take over (its own storage, its own new keys)."""
        db = Storage.memory()
        request = founding_request(db, "V", None, replace=self.org_hash)
        return db, request

    def owners_approve(self, request, revoke="all", since=T):
        event = propose_governed(
            RotateMasterEvent, self.chain.head_hash, new_pubkey=request["new_pubkey"],
            new_encryption_pubkey=request["new_encryption_pubkey"], revoke_devices=revoke, untrusted_since=since,
        )
        approve(event, self.owner.identity_hash, self.owner.local_keypair, self.owner.sigchain.head_hash)
        self.chain.append(event)
        return event


def test_a_clean_installation_takes_over_and_the_old_one_is_cut_off():
    w = World()
    before, after = w.attest_at(w.a, T - 600), w.attest_at(w.a, T + 600)
    assert verify_attestation(before, w.holder.sigchain, w.chain, resolve=w.resolve).ok
    assert verify_attestation(after, w.holder.sigchain, w.chain, resolve=w.resolve).ok     # still trusted: nobody knows yet

    db_b, request = w.fresh_installation()
    assert request["kind"] == "replace" and request["organization"] == w.org_hash
    db_b.save_sigchain(w.owner.sigchain)
    db_b.save_sigchain(w.chain)
    with pytest.raises(IssuerNotReady, match="waiting for the organization's owners"):
        load_owned(db_b, "V", None, None, replace=w.org_hash)

    w.owners_approve(request)                         # the owners decide; nothing the old installation says is used
    assert w.chain.verify(w.resolve, check_current=True) == (True, None)
    assert w.a.device_key.verify_key.to_hex() not in [d.pubkey for d in w.chain.get_active_devices()]   # no window

    db_b.save_sigchain(w.chain)
    b = load_owned(db_b, "V", None, None, replace=w.org_hash)
    assert b.identity_hash == w.org_hash and len(b.identity.sigchain.get_active_devices()) >= 1
    w.chain = b.identity.sigchain

    # the new installation issues; the old device, once trusted, now counts only for what it signed before T
    assert verify_attestation(w.attest_at(b, int(time.time())), w.holder.sigchain, w.chain, resolve=w.resolve).ok
    assert verify_attestation(before, w.holder.sigchain, w.chain, resolve=w.resolve).ok
    bad = verify_attestation(after, w.holder.sigchain, w.chain, resolve=w.resolve)
    assert not bad.ok and bad.code == "issuer_key_not_authorized"

    # the old installation can neither act as the organization nor get back in
    w.db_a.save_sigchain(w.chain)
    with pytest.raises(IssuerNotReady, match="replaced it"):
        load_owned(w.db_a, "V", w.org_hash, None, w.owner.identity_hash)
    old_master_event = RevokeDeviceEvent.create(w.a.identity.local_keypair, "f" * 64, w.chain.head_hash)
    trial = Sigchain(events=list(w.chain.events) + [old_master_event])
    assert "must be signed by master" in trial.verify(w.resolve)[1]


def test_without_a_time_nothing_the_old_device_ever_signed_counts():
    w = World()
    old = w.attest_at(w.a, T - 600)
    _, request = w.fresh_installation()
    w.owners_approve(request, since=None)
    assert w.chain.verify(w.resolve)[0]
    bad = verify_attestation(old, w.holder.sigchain, w.chain, resolve=w.resolve)
    assert not bad.ok and bad.code == "issuer_key_not_authorized"


def test_a_revocation_can_also_say_untrusted_since():
    w = World()
    dev = w.a.device_key.verify_key.to_hex()
    before, after = w.attest_at(w.a, T - 60), w.attest_at(w.a, T + 60)
    w.chain.append(RevokeDeviceEvent.create(w.a.identity.local_keypair, dev, w.chain.head_hash, "stolen", untrusted_since=T))
    assert w.chain.verify(w.resolve)[0]
    assert verify_attestation(before, w.holder.sigchain, w.chain, resolve=w.resolve).ok
    assert not verify_attestation(after, w.holder.sigchain, w.chain, resolve=w.resolve).ok


def test_a_rotation_can_name_devices_and_the_fields_are_checked():
    w = World()
    other = "ab" * 32
    _, request = w.fresh_installation()
    for revoke, since, why in [
        ("everything", None, "revoke_devices"),
        (["nothex"], None, "revoke_devices"),
        (None, T, "without devices"),
        ("all", int(time.time()) + 100000, "future"),
        ("all", -5, "untrusted_since"),
    ]:
        trial = Sigchain(events=list(w.chain.events))
        event = propose_governed(RotateMasterEvent, trial.head_hash, new_pubkey=request["new_pubkey"],
                                 new_encryption_pubkey=request["new_encryption_pubkey"], revoke_devices=revoke, untrusted_since=since)
        approve(event, w.owner.identity_hash, w.owner.local_keypair, w.owner.sigchain.head_hash)
        trial.append(event)
        ok, err = trial.verify(w.resolve)
        assert not ok and why in err, (revoke, since, err)
    # a list that names only some devices leaves the others alone
    w.owners_approve(request, revoke=[other])
    assert w.chain.verify(w.resolve)[0]
    assert w.a.device_key.verify_key.to_hex() in [d.pubkey for d in w.chain.get_active_devices()]


async def test_the_new_installation_finds_out_when_the_owners_approve():
    from aiohttp.test_utils import TestServer
    from nodetide.api import create_app

    w = World()
    db_b, request = w.fresh_installation()
    node_storage = Storage.memory()
    node_storage.save_sigchain(w.owner.sigchain)
    node_storage.save_sigchain(w.chain)
    server = TestServer(create_app(storage=node_storage))
    await server.start_server()
    url = f"http://127.0.0.1:{server.port}"
    try:
        assert await asyncio.to_thread(discover_org, db_b, url) is None          # not yet
        w.owners_approve(request)
        node_storage.save_sigchain(w.chain)
        assert await asyncio.to_thread(discover_org, db_b, url) == w.org_hash    # the organization's key is now ours
        b = await asyncio.to_thread(load_owned, db_b, "V", None, url, None, None, w.org_hash)
        assert b.identity_hash == w.org_hash and db_b.get_issuer_org() == w.org_hash
    finally:
        await server.close()
