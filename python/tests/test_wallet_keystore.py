"""The test wallet can keep its state file encrypted under a key held in the OS key store (macOS Keychain)."""

import importlib.util
import json
from pathlib import Path

import pytest

keyring = pytest.importorskip("keyring")
from keyring.backend import KeyringBackend  # noqa: E402

APP = Path(__file__).resolve().parents[2] / "deploy" / "test" / "wallet" / "app.py"


class MemoryKeyring(KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self.items.get((service, username))

    def set_password(self, service, username, password):
        self.items[(service, username)] = password

    def delete_password(self, service, username):
        self.items.pop((service, username), None)


@pytest.fixture
def store(monkeypatch):
    backend = MemoryKeyring()
    old = keyring.get_keyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(old)


def load_wallet(monkeypatch, data_dir: Path, key_store: str):
    monkeypatch.setenv("NODE_URL", "http://node.invalid")
    monkeypatch.setenv("WALLET_PASSWORD", "pw")
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    if key_store:
        monkeypatch.setenv("WALLET_KEY_STORE", key_store)
    else:
        monkeypatch.delenv("WALLET_KEY_STORE", raising=False)
    spec = importlib.util.spec_from_file_location("wallet_app_under_test", APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_state_is_encrypted_and_survives_a_restart(monkeypatch, tmp_path, store):
    app = load_wallet(monkeypatch, tmp_path, "keychain")
    app.wallet.ensure_identity()
    app.wallet.add_claim("email", "alice@example.org")
    raw = (tmp_path / "wallet.json").read_bytes()
    assert raw.startswith(b"NTW1")
    assert b"alice@example.org" not in raw and b"signing_key" not in raw
    assert len(store.items) == 1

    again = load_wallet(monkeypatch, tmp_path, "keychain")
    assert again.wallet.state["master"] == app.wallet.state["master"]
    assert any(d.claim_type == "email" for d in again.wallet.documents())


def test_plain_state_is_migrated_on_first_start(monkeypatch, tmp_path, store):
    plain = load_wallet(monkeypatch, tmp_path, "")
    plain.wallet.ensure_identity()
    master = plain.wallet.state["master"]
    assert json.loads((tmp_path / "wallet.json").read_text())["master"] == master

    migrated = load_wallet(monkeypatch, tmp_path, "keychain")
    assert migrated.wallet.state["master"] == master
    assert (tmp_path / "wallet.json").read_bytes().startswith(b"NTW1")


def test_missing_or_wrong_key_stops_the_wallet_instead_of_starting_empty(monkeypatch, tmp_path, store):
    app = load_wallet(monkeypatch, tmp_path, "keychain")
    app.wallet.ensure_identity()
    (service, account), key = next(iter(store.items.items()))

    store.items.clear()
    with pytest.raises(SystemExit, match="not in the Keychain"):
        load_wallet(monkeypatch, tmp_path, "keychain")

    store.items[(service, account)] = "00" * 32
    with pytest.raises(SystemExit, match="cannot be decrypted"):
        load_wallet(monkeypatch, tmp_path, "keychain")

    store.items[(service, account)] = key
    assert load_wallet(monkeypatch, tmp_path, "keychain").wallet.state["master"] == app.wallet.state["master"]


def test_an_encrypted_file_is_not_read_without_keychain_mode(monkeypatch, tmp_path, store):
    app = load_wallet(monkeypatch, tmp_path, "keychain")
    app.wallet.ensure_identity()
    with pytest.raises(SystemExit, match="WALLET_KEY_STORE"):
        load_wallet(monkeypatch, tmp_path, "")
