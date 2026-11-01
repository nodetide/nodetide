"""The wallet nags until the identity has an encrypted backup and social recovery, and can restore from the backup."""

import base64
import importlib.util
import json
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api.app import create_app
from nodetide.core.crypto import BACKUP_KDF_ITERATIONS
from nodetide.core.identity import Identity
from nodetide.core.storage import Storage

APP = Path(__file__).resolve().parents[2] / "deploy" / "test" / "wallet" / "app.py"
PASSWORD = "correct horse battery staple"
AUTH = {"Authorization": "Basic " + base64.b64encode(b"wallet:pw").decode()}


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
    spec = importlib.util.spec_from_file_location(f"wallet_protection_{name}", APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.wallet.ensure_identity()
    return module


@pytest.fixture
async def node():
    async with TestClient(TestServer(create_app(storage=Storage.memory()))) as client:
        yield client


@pytest.fixture
async def wallet(node, monkeypatch, tmp_path):
    w = load_wallet(monkeypatch, str(node.make_url("")).rstrip("/"), tmp_path / "a", name="a")
    w.wallet.add_claim("email", "alice@example.org")
    await w.publish()
    return w


async def register(node, n: int) -> list[str]:
    """Other identities on the node, to serve as trustees."""
    hashes = []
    for _ in range(n):
        identity = Identity.create(name="trustee")
        r = await node.post("/api/identities", json={"event": identity.sigchain.to_list()[0]})
        assert r.status in (200, 201)
        hashes.append(identity.identity_hash)
    return hashes


async def test_banner_stays_until_both_steps_are_done(node, wallet):
    p = wallet.protection()
    assert not p["backup_done"] and not p["recovery_done"]
    banner = wallet.protection_banner()
    assert "not protected yet" in banner and banner.count("&#10007;") == 2

    wallet.make_backup(PASSWORD, PASSWORD)
    banner = wallet.protection_banner()
    assert banner.count("&#10003;") == 1 and "Social recovery" in banner

    trustees = await register(node, 3)
    await wallet.configure_recovery("\n".join(trustees), "2")
    assert wallet.protection() | {"backup_at": None} == {
        "backup_done": True, "backup_at": None, "recovery_done": True, "can_set_recovery": True}
    assert wallet.protection_banner() == ""

    # the node has the recovery configuration too
    shown = await (await node.get(f"/api/identities/{wallet.wallet.identity.identity_hash}")).json()
    assert shown["recovery"]["primary_trustees"] == trustees and shown["recovery"]["primary_threshold"] == 2


async def test_a_backup_goes_out_of_date_when_claims_change(node, wallet):
    wallet.make_backup(PASSWORD, PASSWORD)
    assert wallet.protection()["backup_done"]
    wallet.wallet.add_claim("phone", "+359888123456")
    assert not wallet.protection()["backup_done"]
    assert "out of date" in wallet.protection_banner()
    wallet.make_backup(PASSWORD, PASSWORD)
    assert wallet.protection()["backup_done"]


def test_the_backup_is_strongly_encrypted_and_complete(wallet):
    saved = wallet.make_backup(PASSWORD, PASSWORD)
    text = json.dumps(saved)
    assert "alice@example.org" not in text and "signing_key" not in text
    assert saved["encrypted"]["kdf_iterations"] == BACKUP_KDF_ITERATIONS >= 600_000
    assert saved["encrypted"]["cipher"] == "aes-256-gcm" and saved["holds_master_key"] is True
    from nodetide.core.crypto import password_decrypt
    contents = json.loads(password_decrypt(saved["encrypted"], PASSWORD))
    assert set(contents) == {"master", "device", "sigchain", "claims", "attestations"}
    with pytest.raises(ValueError):
        password_decrypt(saved["encrypted"], PASSWORD + "x")


@pytest.mark.parametrize("password,confirm,message", [
    ("short", "short", "at least 12"),
    ("aaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaa", "too easy"),
    ("123456789012345", "123456789012345", "too easy"),
    (PASSWORD, PASSWORD + "!", "differ"),
])
def test_weak_or_mismatched_passwords_make_no_backup(wallet, password, confirm, message):
    with pytest.raises(wallet.WalletError, match=message):
        wallet.make_backup(password, confirm)
    assert not wallet.protection()["backup_done"] and wallet.protection()["backup_at"] is None


async def test_restore_into_an_empty_wallet(node, wallet, monkeypatch, tmp_path):
    saved = wallet.make_backup(PASSWORD, PASSWORD)
    raw = json.dumps(saved).encode()
    fresh = load_wallet(monkeypatch, wallet.NODE_URL, tmp_path / "b", start="pair", name="b")

    with pytest.raises(fresh.WalletError, match="wrong password"):
        fresh.restore_backup(raw, "not the password at all")
    with pytest.raises(fresh.WalletError, match="not a backup"):
        fresh.restore_backup(b"{}", PASSWORD)
    assert "pairing" in fresh.wallet.state  # still empty after the failures

    fresh.restore_backup(raw, PASSWORD)
    assert fresh.wallet.identity.identity_hash == wallet.wallet.identity.identity_hash
    assert fresh.wallet.identity.is_own and {d.value for d in fresh.wallet.documents()} == {"alice@example.org"}
    assert fresh.protection()["backup_done"]  # what was just restored is what the backup covers

    with pytest.raises(fresh.WalletError, match="still empty"):
        fresh.restore_backup(raw, PASSWORD)  # not into a wallet that has an identity


async def test_a_backup_whose_claims_do_not_match_the_chain_is_refused(node, wallet, monkeypatch, tmp_path):
    wallet.wallet.state["claims"] = json.loads(json.dumps(wallet.wallet.state["claims"]))
    next(iter(wallet.wallet.state["claims"].values()))["value"] = "mallory@example.org"
    raw = json.dumps(wallet.make_backup(PASSWORD, PASSWORD)).encode()
    fresh = load_wallet(monkeypatch, wallet.NODE_URL, tmp_path / "c", start="pair", name="c")
    with pytest.raises(fresh.WalletError, match="does not match"):
        fresh.restore_backup(raw, PASSWORD)


async def test_recovery_needs_enough_real_distinct_trustees(node, wallet):
    trustees = await register(node, 3)
    me = wallet.wallet.identity.identity_hash
    cases = [
        ("\n".join(trustees[:2]), "2", "at least 3"),
        ("\n".join(trustees), "1", "between 2 and 3"),
        ("\n".join(trustees), "4", "between 2 and 3"),
        ("\n".join([*trustees[:2], trustees[0]]), "2", "each trustee once"),
        ("\n".join([*trustees[:2], me]), "2", "each trustee once"),
        ("\n".join([*trustees[:2], "ab" * 32]), "2", "does not know"),
        ("\n".join([*trustees[:2], "nonsense"]), "2", "64 hex"),
    ]
    for text, threshold, message in cases:
        with pytest.raises(wallet.WalletError, match=message):
            await wallet.configure_recovery(text, threshold)
    assert not wallet.protection()["recovery_done"]


async def test_a_paired_device_sees_recovery_but_cannot_set_it(node, wallet, monkeypatch, tmp_path):
    second = load_wallet(monkeypatch, wallet.NODE_URL, tmp_path / "d", start="pair", name="d")
    await second.open_pairing()
    await wallet.pairing_approve(second.wallet.state["pairing"]["code"])
    assert await second.check_pairing()

    assert second.protection()["can_set_recovery"] is False
    assert "wallet that holds the master key" in second.protection_banner()
    with pytest.raises(second.WalletError, match="master key"):
        await second.configure_recovery("x", "2")

    await wallet.configure_recovery("\n".join(await register(node, 3)), "2")
    second.wallet.state["sigchain"] = wallet.wallet.state["sigchain"]  # what the next pairing/sync would bring
    assert second.protection()["recovery_done"]
    saved = second.make_backup(PASSWORD, PASSWORD)  # a device backs up its own key and the claim values
    assert saved["holds_master_key"] is False


async def test_pages_show_the_banner_and_the_forms(node, wallet):
    client = TestClient(TestServer(wallet.build_app()))
    await client.start_server()
    try:
        page = await (await client.get("/", headers=AUTH)).text()
        assert "not protected yet" in page and 'id="backup"' in page and 'id="recovery"' in page

        bad = await client.post("/api/backup", data={"password": "short", "confirm": "short"}, headers=AUTH, allow_redirects=False)
        assert bad.status == 303 and "err=" in bad.headers["Location"]
        ok = await client.post("/api/backup", data={"password": PASSWORD, "confirm": PASSWORD}, headers=AUTH)
        assert ok.status == 200 and "attachment" in ok.headers["Content-Disposition"]
        assert json.loads(await ok.read())["format"] == "nodetide-wallet-backup"

        state = await (await client.get("/api/state", headers={**AUTH, "Accept": "application/json"})).json()
        assert state["protection"]["backup_done"] and not state["protection"]["recovery_done"]
    finally:
        await client.close()
