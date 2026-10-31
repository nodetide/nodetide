"""The macOS menu-bar wallet logs the browser in with a one-time launch link instead of the HTTP password."""

import importlib.util
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

APP = Path(__file__).resolve().parents[2] / "deploy" / "test" / "wallet" / "app.py"


def load_wallet(monkeypatch, data_dir: Path, local_app: bool):
    monkeypatch.setenv("NODE_URL", "http://node.invalid")
    monkeypatch.setenv("WALLET_PASSWORD", "pw")
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.delenv("WALLET_KEY_STORE", raising=False)
    if local_app:
        monkeypatch.setenv("WALLET_LOCAL_APP", "1")
    else:
        monkeypatch.delenv("WALLET_LOCAL_APP", raising=False)
    spec = importlib.util.spec_from_file_location("wallet_app_launch_test", APP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def client_for(module) -> TestClient:
    client = TestClient(TestServer(module.build_app()))
    await client.start_server()
    return client


@pytest.mark.asyncio
async def test_launch_link_logs_in_once(monkeypatch, tmp_path):
    module = load_wallet(monkeypatch, tmp_path, local_app=True)
    client = await client_for(module)
    try:
        denied = await client.get("/", allow_redirects=False)
        assert denied.status == 401 and "WWW-Authenticate" not in denied.headers  # no browser password prompt

        link = module.launch_path()
        login = await client.get(link, allow_redirects=False)
        assert login.status == 303 and login.headers["Location"] == "/"
        cookie = login.headers["Set-Cookie"]
        assert "HttpOnly" in cookie and "SameSite=Lax" in cookie

        assert (await client.get("/api/state", headers={"Accept": "application/json"})).status == 200  # cookie kept by the client

        reused = await client.get(link, allow_redirects=False)  # one-time
        assert reused.status == 403
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_expired_or_forged_links_and_the_password_still_work(monkeypatch, tmp_path):
    module = load_wallet(monkeypatch, tmp_path, local_app=True)
    client = await client_for(module)
    try:
        assert (await client.get("/launch?token=forged", allow_redirects=False)).status == 403
        link = module.launch_path()
        module.launch_tokens[link.split("=", 1)[1]] = 0  # expired
        assert (await client.get(link, allow_redirects=False)).status == 403
        assert (await client.get("/", allow_redirects=False)).status == 401
        import aiohttp
        assert (await client.get("/", auth=aiohttp.BasicAuth("wallet", "pw"))).status == 200
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_server_wallet_has_no_launch_route(monkeypatch, tmp_path):
    module = load_wallet(monkeypatch, tmp_path, local_app=False)
    client = await client_for(module)
    try:
        assert (await client.get("/launch?token=x", allow_redirects=False)).status == 401
        denied = await client.get("/", allow_redirects=False)
        assert denied.status == 401 and "WWW-Authenticate" in denied.headers
    finally:
        await client.close()
