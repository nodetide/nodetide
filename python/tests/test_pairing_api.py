"""The pairing rendezvous: public device keys one way, a sealed response the other, for a few minutes."""

import hashlib
import time

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api.app import create_app
from nodetide.core.storage import Storage

SLOT = hashlib.sha256(b"ABCDE-FGHJK").hexdigest()
REQUEST = {"device_pubkey": "ab" * 32, "device_encryption_pubkey": "cd" * 32, "label": "Mac"}
RESPONSE = {"from_encryption_pubkey": "ef" * 32, "sealed": "c2VhbGVk"}


@pytest.fixture
async def client():
    app = create_app(storage=Storage.memory())
    async with TestClient(TestServer(app)) as c:
        c.app_ = app
        yield c


async def test_open_read_respond_and_close(client):
    r = await client.post("/api/pairing", json={"slot": SLOT, "request": REQUEST})
    assert r.status == 201

    seen = await (await client.get(f"/api/pairing/{SLOT}")).json()
    assert seen["request"] == REQUEST and seen["response"] is None

    assert (await client.put(f"/api/pairing/{SLOT}/response", json={"response": RESPONSE})).status == 201
    assert (await client.put(f"/api/pairing/{SLOT}/response", json={"response": RESPONSE})).status == 409  # once

    done = await (await client.get(f"/api/pairing/{SLOT}")).json()
    assert done["response"] == RESPONSE

    assert (await client.delete(f"/api/pairing/{SLOT}")).status == 204
    assert (await client.get(f"/api/pairing/{SLOT}")).status == 404


async def test_unknown_malformed_and_duplicate_slots(client):
    assert (await client.get(f"/api/pairing/{'0' * 64}")).status == 404
    assert (await client.get("/api/pairing/not-a-slot")).status == 404
    assert (await client.put(f"/api/pairing/{'0' * 64}/response", json={"response": RESPONSE})).status == 404

    assert (await client.post("/api/pairing", json={"slot": SLOT, "request": REQUEST})).status == 201
    assert (await client.post("/api/pairing", json={"slot": SLOT, "request": REQUEST})).status == 409


@pytest.mark.parametrize("bad", [
    {"slot": "short", "request": REQUEST},
    {"slot": SLOT, "request": {**REQUEST, "device_pubkey": "zz" * 32}},
    {"slot": SLOT, "request": {**REQUEST, "label": ""}},
    {"slot": SLOT, "request": {**REQUEST, "label": "x" * 65}},
    {"slot": SLOT, "request": "nope"},
])
async def test_bad_requests_are_refused(client, bad):
    assert (await client.post("/api/pairing", json=bad)).status == 400


async def test_bad_responses_are_refused(client):
    await client.post("/api/pairing", json={"slot": SLOT, "request": REQUEST})
    for bad in ({"response": {"sealed": "x"}}, {"response": {**RESPONSE, "sealed": ""}}, {"response": "x"}):
        assert (await client.put(f"/api/pairing/{SLOT}/response", json=bad)).status == 400


async def test_slots_expire_and_are_capped(client):
    await client.post("/api/pairing", json={"slot": SLOT, "request": REQUEST})
    client.app_["pairing_slots"][SLOT].expires_at = int(time.time()) - 1
    assert (await client.get(f"/api/pairing/{SLOT}")).status == 404

    from nodetide.api import pairing
    pairing.MAX_SLOTS, old = 2, pairing.MAX_SLOTS
    try:
        for i in range(2):
            assert (await client.post("/api/pairing", json={"slot": f"{i:064x}", "request": REQUEST})).status == 201
        assert (await client.post("/api/pairing", json={"slot": f"{9:064x}", "request": REQUEST})).status == 503
    finally:
        pairing.MAX_SLOTS = old


async def test_posting_a_known_genesis_again_never_truncates_the_chain(client):
    """The genesis event is public; replaying it must not wipe the identity's later events."""
    from nodetide.core.identity import DeviceCapability, Identity

    identity = Identity.create(name="victim")
    genesis = identity.sigchain.to_list()[0]
    assert (await client.post("/api/identities", json={"event": genesis})).status == 201
    identity.add_device("laptop", capabilities=[DeviceCapability.AUTHENTICATE])
    event = identity.sigchain.to_list()[1]
    assert (await client.post(f"/api/identities/{identity.identity_hash}/events", json={"event": event})).status in (200, 201)

    again = await client.post("/api/identities", json={"event": genesis})
    assert again.status == 200  # idempotent
    chain = await (await client.get(f"/api/identities/{identity.identity_hash}/sigchain")).json()
    assert chain["length"] == 2


async def test_organization_events_need_owner_approvals_and_the_node_checks_them(client):
    from nodetide.core.crypto import KeyPair
    from nodetide.core.identity import (
        AddDeviceEvent, GenesisEvent, Identity, IdentityType, approve, propose_governed,
    )

    me = Identity.create(name="me")
    assert (await client.post("/api/identities", json={"event": me.sigchain.to_list()[0]})).status == 201

    key = KeyPair.generate()
    genesis = GenesisEvent.create(
        key, identity_type=IdentityType.ORGANIZATION, name="org",
        owners=[{"identity": me.identity_hash, "weight": 100}],
    )
    # without the owner's approval the node refuses it
    assert (await client.post("/api/identities", json={"event": genesis.to_dict()})).status == 400
    approve(genesis, me.identity_hash, me.local_keypair, me.sigchain.head_hash)
    created = await client.post("/api/identities", json={"event": genesis.to_dict()})
    assert created.status == 201
    org = (await created.json())["identity_hash"]

    device = KeyPair.generate()
    event = propose_governed(
        AddDeviceEvent, genesis.event_hash(), device_pubkey=device.verify_key.to_hex(),
        device_encryption_pubkey=device.public_encryption_key.to_hex(), label="verifier", capabilities=["manage_claims"],
    )
    # unapproved: refused, and the chain stays as it was
    assert (await client.post(f"/api/identities/{org}/events", json={"event": event.to_dict()})).status == 400
    approve(event, me.identity_hash, me.local_keypair, me.sigchain.head_hash)
    assert (await client.post(f"/api/identities/{org}/events", json={"event": event.to_dict()})).status == 201
    chain = await (await client.get(f"/api/identities/{org}/sigchain")).json()
    assert chain["length"] == 2
    info = await (await client.get(f"/api/identities/{org}")).json()
    assert info["verified"] is True
    # replaying the organization's genesis stays harmless
    assert (await client.post("/api/identities", json={"event": genesis.to_dict()})).status == 200


async def test_social_recovery_through_the_node(client):
    from nodetide.core.crypto import KeyPair
    from nodetide.core.identity import Identity, SocialRecoveryEvent, sign_recovery
    import json as _json

    async def put(ident):
        assert (await client.post("/api/identities", json={"event": ident.sigchain.to_list()[0]})).status == 201
        for e in ident.sigchain.to_list()[1:]:
            r = await client.post(f"/api/identities/{ident.identity_hash}/events", json={"event": e})
            assert r.status == 201, await r.text()

    me, a, b, c = (Identity.create(name=n) for n in "mabc")
    for t in (a, b, c):
        await put(t)
    me.set_recovery([a.identity_hash, b.identity_hash, c.identity_hash], 2)
    await put(me)

    new = KeyPair.generate()
    start = await client.post(f"/api/identities/{me.identity_hash}/recovery/initiate", json={
        "new_pubkey": new.verify_key.to_hex(), "new_encryption_pubkey": new.public_encryption_key.to_hex()})
    assert start.status == 201
    st = await start.json()
    rid, prev = st["recovery_id"], st["prev"]
    assert prev == me.sigchain.head_hash

    def sig(t, **over):
        rec = sign_recovery(t.identity_hash, t.local_keypair, t.sigchain.head_hash, me.identity_hash, prev,
                            new.verify_key.to_hex(), new.public_encryption_key.to_hex())
        rec.update(over)
        return rec

    url = f"/api/identities/{me.identity_hash}/recovery/{rid}/sign"
    assert (await client.post(url, json={"record": sig(a, signature="00" * 64)})).status == 400  # forged
    stranger = Identity.create(name="s")
    await put(stranger)
    assert (await client.post(url, json={"record": sig(stranger)})).status == 403

    r = await client.post(url, json={"record": sig(a)})
    assert r.status == 200 and (await r.json())["status"] == "pending"
    r = await client.post(url, json={"record": sig(c)})
    done = await r.json()
    assert done["status"] == "complete" and len(done["signatures"]) == 2

    ev = SocialRecoveryEvent(
        type=None, timestamp=1, prev=prev, signature="", signed_by=new.verify_key.to_hex(),
        new_pubkey=new.verify_key.to_hex(), new_encryption_pubkey=new.public_encryption_key.to_hex(),
        recovery_signatures=[s["record"] for s in done["signatures"]],
    )
    ev.signature = new.sign_hex(_json.dumps(ev.signable_dict(), sort_keys=True, separators=(",", ":")).encode())
    # an event with a missing trustee signature is refused
    bad = ev.to_dict(); bad["recovery_signatures"] = bad["recovery_signatures"][:1]
    assert (await client.post(f"/api/identities/{me.identity_hash}/events", json={"event": bad})).status == 400
    ok = await client.post(f"/api/identities/{me.identity_hash}/events", json={"event": ev.to_dict()})
    assert ok.status == 201, await ok.text()
    info = await (await client.get(f"/api/identities/{me.identity_hash}")).json()
    assert info["master_pubkey"] == new.verify_key.to_hex() and info["verified"] is True
