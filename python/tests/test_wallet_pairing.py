"""A second wallet becomes a device of the first one's identity through the node's pairing rendezvous."""

import importlib.util
import json
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api.app import create_app
from nodetide.core.storage import Storage

APP = Path(__file__).resolve().parents[2] / "deploy" / "test" / "wallet" / "app.py"


def load_wallet(monkeypatch, node_url: str, data_dir: Path, start: str = "", name: str = "w"):
    monkeypatch.setenv("NODE_URL", node_url)
    monkeypatch.setenv("WALLET_PASSWORD", "pw")
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("WALLET_DEVICE_LABEL", "Mac")
    monkeypatch.delenv("WALLET_KEY_STORE", raising=False)
    monkeypatch.delenv("WALLET_LOCAL_APP", raising=False)
    if start:
        monkeypatch.setenv("WALLET_START", start)
    else:
        monkeypatch.delenv("WALLET_START", raising=False)
    spec = importlib.util.spec_from_file_location(f"wallet_pairing_{name}", APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.wallet.ensure_identity()
    return module


@pytest.fixture
async def node():
    async with TestClient(TestServer(create_app(storage=Storage.memory()))) as client:
        yield client


@pytest.fixture
async def pair(node, monkeypatch, tmp_path):
    url = str(node.make_url("")).rstrip("/")
    first = load_wallet(monkeypatch, url, tmp_path / "a", name="a")
    first.wallet.add_claim("email", "alice@example.org")
    first.wallet.add_claim("phone", "+359888123456")
    await first.publish()
    second = load_wallet(monkeypatch, url, tmp_path / "b", start="pair", name="b")
    return first, second


async def sigchain_length(node, identity: str) -> int:
    body = await (await node.get(f"/api/identities/{identity}/sigchain")).json()
    return body["length"] + body["content_length"]  # control events plus content events


async def test_second_wallet_pairs_and_then_adds_claims_as_a_device(node, pair):
    first, second = pair
    identity = first.wallet.identity.identity_hash
    first.wallet.state["attestations"].append({"claim_id": next(iter(first.wallet.state["claims"])), "method": "test",
                                               "assurance": "low", "expires_at": 2**40})  # opaque to pairing
    assert "pairing" in second.wallet.state and "sigchain" not in second.wallet.state
    assert not await second.check_pairing() is True  # opens a code, no answer yet
    code = second.wallet.state["pairing"]["code"]

    label = await first.pairing_approve(first.show_code(code).lower())  # typed by hand, any case, with the dash
    assert label == "Mac"
    assert await second.check_pairing() is True

    # same identity, same claims, no master key on the new device
    assert second.wallet.identity.identity_hash == identity
    assert "master" not in second.wallet.state and not second.wallet.identity.is_own
    assert {d.claim_type for d in second.wallet.documents()} == {"email", "phone"}
    assert len(second.wallet.state["attestations"]) == 1
    labels = {d.label for d in second.wallet.identity.sigchain.get_active_devices()}
    assert labels == {"Primary", "test wallet", "Mac"}  # the master key, the first wallet's device, this one

    # the node accepts claims signed by the paired device
    before = await sigchain_length(node, identity)
    second.wallet.add_claim("birthdate", "1990-05-17")
    await second.publish()
    assert await sigchain_length(node, identity) == before + 1
    assert second.wallet.identity.verify()[0]


async def test_a_paired_device_cannot_add_devices(node, pair, monkeypatch):
    first, second = pair
    await second.open_pairing()
    await first.pairing_approve(second.wallet.state["pairing"]["code"])
    assert await second.check_pairing()
    third = load_wallet(monkeypatch, second.NODE_URL, Path(second.DATA_DIR).parent / "c", start="pair", name="c")
    await third.open_pairing()
    with pytest.raises(second.WalletError, match="master key"):
        await second.pairing_approve(third.wallet.state["pairing"]["code"])


async def test_wrong_codes_and_double_answers(node, pair):
    first, second = pair
    with pytest.raises(first.WalletError, match="not a pairing code"):
        await first.pairing_approve("short")
    with pytest.raises(first.WalletError, match="no device is waiting"):
        await first.pairing_approve("ABCDEFGHJK")
    await second.open_pairing()
    code = second.wallet.state["pairing"]["code"]
    await first.pairing_approve(code)
    with pytest.raises(first.WalletError, match="already been answered"):
        await first.pairing_approve(code)


async def test_an_answer_not_from_a_device_of_the_identity_is_refused(node, pair, monkeypatch, tmp_path):
    first, second = pair
    await second.open_pairing()
    code = second.wallet.state["pairing"]["code"]
    # an impostor answers the slot with a payload sealed by its own key
    from nodetide.core.crypto import EncryptionPublicKey, KeyPair
    import base64
    impostor = KeyPair.generate()
    device = KeyPair.from_dict(second.wallet.state["pairing"]["device"])
    payload = json.dumps({"sigchain": first.wallet.state["sigchain"], "claims": {}, "attestations": []}).encode()
    sealed = device.public_encryption_key.encrypt(payload, impostor.encryption_key)
    status, _ = await second.node("PUT", f"/api/pairing/{second.pairing_slot(code)}/response", json={"response": {
        "from_encryption_pubkey": impostor.public_encryption_key.to_hex(), "sealed": base64.b64encode(sealed).decode()}})
    assert status == 201
    with pytest.raises(second.WalletError, match="not authorized this device|not come from a device"):
        await second.check_pairing()
    assert "pairing" in second.wallet.state and "sigchain" not in second.wallet.state


async def test_a_tampered_claim_is_refused(node, pair):
    first, second = pair
    await second.open_pairing()
    code = second.wallet.state["pairing"]["code"]
    claims = json.loads(json.dumps(first.wallet.state["claims"]))
    next(iter(claims.values()))["value"] = "mallory@example.org"
    first.wallet.state["claims"] = claims  # a lying answer: the value no longer matches the chain's commitment
    await first.pairing_approve(code)
    with pytest.raises(second.WalletError, match="does not match"):
        await second.check_pairing()


async def test_pages_follow_the_state(node, pair, monkeypatch):
    first, second = pair
    app_b = TestClient(TestServer(second.build_app()))
    app_a = TestClient(TestServer(first.build_app()))
    await app_b.start_server()
    await app_a.start_server()
    auth = {"Authorization": "Basic " + __import__("base64").b64encode(b"wallet:pw").decode()}
    try:
        page = await (await app_b.get("/", headers=auth)).text()
        code = second.wallet.state["pairing"]["code"]
        assert second.show_code(code) in page and "Pair this wallet" in page
        assert (await app_b.get("/api/state", headers={**auth, "Accept": "application/json"})).status == 409

        preview = await app_a.post("/api/devices/preview", data={"code": second.show_code(code)}, headers=auth)
        assert preview.status == 200 and "Add the device" in await preview.text()
        approved = await app_a.post("/api/devices/approve", data={"code": second.show_code(code)}, headers=auth,
                                    allow_redirects=False)
        assert approved.status == 303

        paired = await app_b.get("/", headers=auth, allow_redirects=False)
        assert paired.status == 303  # the pairing page redirects once the answer is in
        dashboard = await (await app_b.get("/", headers=auth)).text()
        assert "Devices" in dashboard and "(this device)" in dashboard and "master key" in dashboard
    finally:
        await app_a.close()
        await app_b.close()
