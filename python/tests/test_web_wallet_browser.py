"""The browser wallet: claims, email verification against a real verifier service on another origin, persistence and backup.

Same requirements as test_web_protection_browser (Chrome, internet for the CDN scripts):
    NODETIDE_BROWSER_TESTS=1 pytest tests/test_web_wallet_browser.py
"""

import asyncio
import json
import os
import re
import socket
import subprocess
import tempfile
import hashlib
import base64
import secrets
from urllib.parse import parse_qs, quote, urlsplit

import aiohttp
from aiohttp.test_utils import TestServer

from nodetide.api.app import create_app
from nodetide.core.storage import Storage
from nodetide.oidc import OIDCClient, OIDCConfig
from nodetide.verifiers import EmailVerifier, NodeIssuer
from nodetide.verifiers.mail import MemorySender
from nodetide.verifiers.service import create_verifier_app
from tests.test_web_protection_browser import CDP_PORT, CHROME, WEB, Page, comp, pytestmark  # noqa: F401


async def test_claim_verification_persistence_and_backup(monkeypatch):
    verifier_storage = Storage.memory()
    sender = MemorySender()
    verifier = EmailVerifier(verifier_storage, NodeIssuer.load_or_create(verifier_storage, "Browser Test Verifier"), sender)
    verifier_server = TestServer(create_verifier_app(verifier_storage, verifier, "https://verifier.test"))
    await verifier_server.start_server()
    monkeypatch.setenv("NODETIDE_WEB_VERIFIER_URL", f"http://127.0.0.1:{verifier_server.port}")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    base = issuer = f"http://127.0.0.1:{port}"
    redirect = "https://app.example.com/cb"
    config = OIDCConfig(issuer=issuer, clients={"spa": OIDCClient("spa", "Demo SPA", (redirect,))},
                        email_issuers=[verifier.issuer.identity_hash])
    node = TestServer(create_app(storage=Storage.memory(), web_root=str(WEB), oidc_config=config), port=port)
    await node.start_server()
    chrome = None
    try:
        async with aiohttp.ClientSession() as http:
            chrome = subprocess.Popen(
                [CHROME, "--headless=new", f"--remote-debugging-port={CDP_PORT}", f"--user-data-dir={tempfile.mkdtemp()}",
                 "--no-first-run", "--disable-gpu", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tabs = None
            for _ in range(50):
                try:
                    async with http.get(f"http://127.0.0.1:{CDP_PORT}/json") as r:
                        tabs = await r.json()
                        break
                except aiohttp.ClientError:
                    await asyncio.sleep(0.2)
            tab = next(t for t in tabs if t["type"] == "page")
            async with http.ws_connect(tab["webSocketDebuggerUrl"]) as ws:
                page = Page(ws)
                await page.call("Runtime.enable")
                await page.call("Page.enable")

                async def load():
                    await page.call("Page.navigate", url=base + "/")
                    for _ in range(100):
                        if await page.js("!!(window.Alpine && Alpine.store('wallet'))", wait=False):
                            break
                        await asyncio.sleep(0.2)
                    await asyncio.sleep(0.5)

                async def attempt(expr):
                    await page.js("Alpine.store('app').error=null")
                    await page.js(f"(async()=>{{{expr}}})()")
                    return await page.js("Alpine.store('app').error")

                attempt_js = attempt
                wallet = comp("[x-data=walletUI]")
                await load()
                await page.js("""window.__files=[]; const orig=URL.createObjectURL;
                    URL.createObjectURL=(b)=>{ b.text().then(t=>window.__files.push(t)); return orig(b); };""", wait=False)

                # a name with non-ASCII letters: the node only accepts it if the client signs what Python reproduces
                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'Алекс',
                    method:'password',password:'wallet-pass-12',confirmPassword:'wallet-pass-12',distributionPoints:''}};
                    await m.createIdentity();}})()""")
                await asyncio.sleep(1)
                identity = await page.js("Alpine.store('identity').activeHash")
                async with http.get(f"{base}/api/identities/{identity}") as r:
                    info = await r.json()
                assert info["name"] == "Алекс" and info["verified"] is True

                # locked until the password is given; wrong password refused
                assert await page.js("Alpine.store('wallet').unlocked") is False
                assert "Could not unlock" in await attempt(f"const c={wallet}; c.password='nope'; await c.unlock();")
                assert await attempt(f"const c={wallet}; c.password='wallet-pass-12'; await c.unlock();") is None
                assert await page.js("Alpine.store('wallet').unlocked") is True

                # claims are checked like Python does
                assert "invalid email" in await attempt(f"const c={wallet}; c.email='not-an-address'; await c.addEmail();")
                assert "E.164" in await attempt(f"const c={wallet}; c.phone='12345'; await c.addPhone();")
                assert await attempt(f"const c={wallet}; c.email='  Alice@Example.COM '; await c.addEmail();") is None
                claims = await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))")
                assert len(claims) == 1 and claims[0]["value"] == "Alice@example.com" and claims[0]["verified"] is False
                claim_id = claims[0]["id"]
                async with http.get(f"{base}/api/identities/{identity}/sigchain") as r:
                    chain = await r.json()
                added = [e for e in chain["events"] if e["type"] == "add_claim"]
                assert len(added) == 1 and added[0]["claim_id"] == claim_id and "alice" not in json.dumps(added[0]).lower()

                # verification: the verifier (another origin) recomputes the commitment and mails a code
                assert await attempt(f"await {wallet}.verify({json.dumps(claim_id)});") is None
                assert len(sender.outbox) == 1 and sender.outbox[0]["to"] == "Alice@example.com"
                code = re.search(r"Verification code: ([A-Z0-9]+)", sender.outbox[0]["body"]).group(1)
                assert await attempt(f"const c={wallet}; c.codes[{json.dumps(claim_id)}]='WRONGONE'; await c.confirm({json.dumps(claim_id)});")
                assert await attempt(f"const c={wallet}; c.codes[{json.dumps(claim_id)}]={json.dumps(code)}; await c.confirm({json.dumps(claim_id)});") is None
                claims = await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))")
                assert claims[0]["verified"] is True and claims[0]["method"] == "email_code" and claims[0]["issuer"] == "Browser Test Verifier"

                # the web client's device now carries real capabilities
                async with http.get(f"{base}/api/identities/{identity}") as r:
                    info = await r.json()
                assert any("authenticate" in d["capabilities"] and "manage_claims" in d["capabilities"] for d in info["devices"])


                # --- sign in to an application with this wallet (the node's OIDC page links to /signin?link=...) ---------
                code_verifier = secrets.token_urlsafe(32)
                code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
                async with http.get(f"{base}/oidc/authorize", allow_redirects=False, params={
                        "client_id": "spa", "redirect_uri": redirect, "response_type": "code", "scope": "openid profile email",
                        "state": "st", "nonce": "n", "code_challenge": code_challenge, "code_challenge_method": "S256"}) as r:
                    assert r.status == 302
                    login_path, _, login_secret = r.headers["Location"].partition("#")
                    login_id = login_path.rsplit("/", 1)[1]
                challenge_url = f"{issuer}/oidc/login/{login_id}/challenge"
                await page.call("Page.navigate", url=f"{base}/signin?link={quote(challenge_url, safe='')}")
                for _ in range(100):
                    if await page.js("!!(window.Alpine && Alpine.store('wallet'))", wait=False):
                        break
                    await asyncio.sleep(0.2)
                await asyncio.sleep(0.8)
                signin = comp("[x-data=signinUI]")
                assert await page.js("Alpine.store('app').currentView") == "signin"
                assert await page.js("window.location.pathname") == "/"  # the link was consumed, not left in the address bar
                assert await attempt_js(f"const c={signin}; c.password='nope'; await c.unlock();") is not None
                assert await attempt_js(f"const c={signin}; c.password='wallet-pass-12'; await c.unlock();") is None
                await asyncio.sleep(0.8)
                view = await page.js(f"JSON.parse(JSON.stringify({signin}.preview.candidateView))")
                assert await page.js(f"{signin}.preview.client") == "Demo SPA"
                assert [c["claim_type"] for c in view] == ["email"] and view[0]["value"] == "Alice@example.com" and view[0]["default"] is True
                # a sign-in for a different origin is refused outright
                assert "only to its own node" in await attempt_js(
                    f"const c={signin}; c.link='https://evil.example/oidc/login/x/challenge'; await c.load();")
                assert await attempt_js(f"const c={signin}; await c.approve();") is None
                async with http.get(f"{base}/oidc/login/{login_id}/status", headers={"X-Login-Secret": login_secret}) as r:
                    status = await r.json()
                assert status["status"] == "approved", status
                code = parse_qs(urlsplit(status["redirect_to"]).query)["code"][0]
                async with http.post(f"{base}/oidc/token", data={
                        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "client_id": "spa",
                        "code_verifier": code_verifier}) as r:
                    tokens = await r.json()
                async with http.get(f"{base}/oidc/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"}) as r:
                    userinfo = await r.json()
                assert userinfo["sub"] == identity and userinfo["email"] == "Alice@example.com" and userinfo["email_verified"] is True

                await load()

                # a reload drops the keys from memory; the data stays, encrypted
                stored = await page.js(f"JSON.stringify(Object.entries(localStorage).filter(([k])=>k.startsWith('nodetide_wallet_')))")
                assert "nodetide_wallet_" in stored and "alice" not in stored.lower() and "example.com" not in stored.lower()
                await load()
                assert await page.js("Alpine.store('wallet').unlocked") is False
                assert await attempt(f"const c={wallet}; c.password='wallet-pass-12'; await c.unlock();") is None
                claims = await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))")
                assert len(claims) == 1 and claims[0]["verified"] is True

                # the backup carries the claim values; after losing the browser they come back
                async def backup():
                    return await attempt(f"const c={comp('[x-data=protectionUI]')}; c.backup={{identityPassword:'wallet-pass-12',"
                                         "password:'correct horse battery',confirm:'correct horse battery'}; await c.makeBackup();")
                await page.js("""window.__files=[]; const orig=URL.createObjectURL;
                    URL.createObjectURL=(b)=>{ b.text().then(t=>window.__files.push(t)); return orig(b); };""", wait=False)
                assert await backup() is None
                await asyncio.sleep(0.5)
                files = await page.js("window.__files")
                assert "alice" not in files[0].lower()  # encrypted, like everything else in it
                await page.js("localStorage.clear()", wait=False)
                await load()
                assert await page.js("Alpine.store('identity').identities.length") == 0
                restored = await attempt(
                    f"const c={comp('[x-data=settingsManager]')}; c.restoreFile={{text:async()=>{json.dumps(files[0])}}};"
                    "c.restorePassword='correct horse battery'; c.restoreLocalPassword='new-local-pass-9';"
                    "c.restoreLocalConfirmPassword='new-local-pass-9'; await c.restoreIdentity();")
                assert restored is None
                await page.js(f"Alpine.store('identity').setActive({json.dumps(identity)})")
                await asyncio.sleep(0.5)
                assert await attempt(f"const c={wallet}; c.password='new-local-pass-9'; await c.unlock();") is None
                claims = await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))")
                assert len(claims) == 1 and claims[0]["verified"] is True and claims[0]["value"] == "Alice@example.com"
    finally:
        if chrome:
            chrome.terminate()
        await node.close()
        await verifier_server.close()


async def test_passkey_unlocks_the_wallet():
    """A virtual authenticator with the PRF extension stands in for Touch ID / a security key."""
    node = TestServer(create_app(storage=Storage.memory(), web_root=str(WEB)))
    await node.start_server()
    base = f"http://localhost:{node.port}"  # a WebAuthn RP id must be a domain name, not an IP address
    chrome = None
    try:
        async with aiohttp.ClientSession() as http:
            chrome = subprocess.Popen(
                [CHROME, "--headless=new", f"--remote-debugging-port={CDP_PORT}", f"--user-data-dir={tempfile.mkdtemp()}",
                 "--no-first-run", "--disable-gpu", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tabs = None
            for _ in range(50):
                try:
                    async with http.get(f"http://127.0.0.1:{CDP_PORT}/json") as r:
                        tabs = await r.json()
                        break
                except aiohttp.ClientError:
                    await asyncio.sleep(0.2)
            tab = next(t for t in tabs if t["type"] == "page")
            async with http.ws_connect(tab["webSocketDebuggerUrl"]) as ws:
                page = Page(ws)
                await page.call("Runtime.enable")
                await page.call("Page.enable")
                await page.call("WebAuthn.enable")
                await page.call("WebAuthn.addVirtualAuthenticator", options={
                    "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
                    "isUserVerified": True, "hasPrf": True, "automaticPresenceSimulation": True})

                async def load():
                    await page.call("Page.navigate", url=base + "/")
                    for _ in range(100):
                        if await page.js("!!(window.Alpine && Alpine.store('wallet'))", wait=False):
                            break
                        await asyncio.sleep(0.2)
                    await asyncio.sleep(0.5)

                async def attempt(expr):
                    await page.js("Alpine.store('app').error=null")
                    await page.js(f"(async()=>{{{expr}}})()")
                    return await page.js("Alpine.store('app').error")

                wallet = comp("[x-data=walletUI]")
                await load()
                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'pk',
                    method:'password',password:'passkey-pass-12',confirmPassword:'passkey-pass-12',distributionPoints:''}};
                    await m.createIdentity();}})()""")
                await asyncio.sleep(1)
                assert await page.js(f"{wallet}.canPasskey") is True and await page.js(f"{wallet}.hasPasskey") is False
                assert await attempt(f"const c={wallet}; c.password='passkey-pass-12'; await c.unlock();") is None
                assert await attempt(f"await {wallet}.addPasskey();") is None
                assert await page.js(f"{wallet}.hasPasskey") is True
                stored = await page.js("localStorage.getItem('nodetide_identities')")
                assert "passkey-pass-12" not in stored and '"passkey"' in stored  # the password is only there wrapped

                await load()  # keys leave memory
                assert await page.js("Alpine.store('wallet').unlocked") is False
                assert await attempt(f"await {wallet}.unlockWithPasskey();") is None
                assert await page.js("Alpine.store('wallet').unlocked") is True

                # the password still works, and removing the passkey takes the shortcut away
                await load()
                assert await attempt(f"const c={wallet}; c.password='passkey-pass-12'; await c.unlock();") is None
                await page.js(f"{wallet}.removePasskey()")
                await load()
                assert await page.js(f"{wallet}.hasPasskey") is False
                assert "No passkey" in await attempt(f"await {wallet}.unlockWithPasskey();")

                # an identity made WITH a passkey has no password at all
                assert await page.js(f"{comp('[x-data=identityManager]')}.webauthnSupported") is True
                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'no-password',
                    method:'webauthn',password:'',confirmPassword:'',distributionPoints:''}}; await m.createIdentity();}})()""")
                await asyncio.sleep(1.5)
                made = await page.js("JSON.parse(JSON.stringify(Alpine.store('identity').activeIdentity))")
                assert made["name"] == "no-password" and made["storageMethod"] == "webauthn" and made["passkey"]
                async with http.get(f"{base}/api/identities/{made['identityHash']}") as r:
                    assert r.status == 200 and (await r.json())["verified"] is True
                await load()
                assert await attempt(f"const c={wallet}; await c.unlockWithPasskey();") is None
                assert await page.js("Alpine.store('wallet').unlocked") is True
                # the typed-password forms accept an empty field for such an identity: the passkey stands in
                await page.js("""window.__files=[]; const orig=URL.createObjectURL;
                    URL.createObjectURL=(b)=>{ b.text().then(t=>window.__files.push(t)); return orig(b); };""", wait=False)
                assert await attempt(f"const c={comp('[x-data=protectionUI]')}; c.backup={{identityPassword:'',"
                                     "password:'correct horse battery',confirm:'correct horse battery'}; await c.makeBackup();") is None
                await asyncio.sleep(0.5)
                assert json.loads((await page.js("window.__files"))[0])["holds_master_key"] is True
    finally:
        if chrome:
            chrome.terminate()
        await node.close()
