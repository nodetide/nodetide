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
