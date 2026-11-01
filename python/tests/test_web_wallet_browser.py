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

                # the organizations card is on the My Identity tab, visible even while the wallet is locked
                await page.js("Alpine.store('app').setView('identity')")
                assert await page.js("""(()=>{const e=[...document.querySelectorAll('.card-title')]
                    .find(x=>x.textContent.includes('Organizations you own')); return !!e && e.offsetParent!==null})()""")

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
                # the same address again (any case, spaces) is refused; the wallet holds one claim per value
                assert "already in your wallet" in await attempt(f"const c={wallet}; c.email=' ALICE@example.com'; await c.addEmail();")
                assert len(await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))")) == 1
                async with http.get(f"{base}/api/identities/{identity}/sigchain") as r:
                    chain = await r.json()
                added = [e for e in chain["events"] if e["type"] == "add_claim"]
                assert len(added) == 1 and added[0]["claim_id"] == claim_id and "alice" not in json.dumps(added[0]).lower()

                # renouncing gives a claim up on the chain but keeps it (hidden) with its history
                assert await attempt(f"const c={wallet}; c.phone='+359 88 123 4567'; await c.addPhone();") is None
                phone = [c for c in await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))") if c["type"] == "phone"][0]
                await page.js("window.confirm = () => true")
                assert await attempt(f"await {wallet}.renounce({json.dumps(phone['id'])});") is None
                visible = await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))")
                assert [c["type"] for c in visible] == ["email"]                       # hidden by default
                assert await page.js(f"{wallet}.renouncedCount") == 1
                await page.js(f"{wallet}.showRenounced = true; {wallet}.refresh()")
                shown = await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))")
                assert [c["type"] for c in shown] == ["email", "phone"] and shown[1]["renounced"] is True and shown[1]["codeable"] is False
                await page.js(f"{wallet}.showRenounced = false; {wallet}.refresh()")
                async with http.get(f"{base}/api/identities/{identity}/sigchain") as r:
                    revoked = [e for e in (await r.json())["events"] if e["type"] == "revoke_claim"]
                assert len(revoked) == 1 and revoked[0]["claim_id"] == phone["id"]
                async with http.get(f"{base}/api/identities/{identity}") as r:
                    assert (await r.json())["verified"] is True
                # its timeline is still readable: claimed, then renounced, both on the chain
                await page.js(f"{wallet}.toggle({json.dumps(phone['id'])})")
                await asyncio.sleep(0.5)
                tl = await page.js(f"JSON.parse(JSON.stringify({wallet}.details[{json.dumps(phone['id'])}]))")
                assert [e["label"].split(" ")[0] for e in tl["entries"] if e["source"] == "chain"] == ["Claimed", "Renounced"]
                # the value can be claimed again, and a renounced one is never offered or verified
                assert await attempt(f"const c={wallet}; c.phone='+359881234567'; await c.addPhone();") is None
                again = [c for c in await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))") if c["type"] == "phone"][0]
                assert again["id"] != phone["id"]
                assert await attempt(f"await {wallet}.renounce({json.dumps(again['id'])});") is None

                # verification: the verifier (another origin) recomputes the commitment and mails a code
                assert await attempt(f"await {wallet}.verify({json.dumps(claim_id)});") is None
                assert len(sender.outbox) == 1 and sender.outbox[0]["to"] == "Alice@example.com"
                code = re.search(r"Verification code: ([A-Z0-9]+)", sender.outbox[0]["body"]).group(1)
                assert await attempt(f"const c={wallet}; c.codes[{json.dumps(claim_id)}]='WRONGONE'; await c.confirm({json.dumps(claim_id)});")
                assert await attempt(f"const c={wallet}; c.codes[{json.dumps(claim_id)}]={json.dumps(code)}; await c.confirm({json.dumps(claim_id)});") is None
                claims = await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))")
                assert claims[0]["verified"] is True and claims[0]["method"] == "email_code" and claims[0]["issuer"] == "Browser Test Verifier"

                # the timeline of a verified claim: chain event, code request, attestation; raw events; explorer link
                await page.js(f"{wallet}.toggle({json.dumps(claim_id)})")
                await asyncio.sleep(0.5)
                tl = await page.js(f"JSON.parse(JSON.stringify({wallet}.details[{json.dumps(claim_id)}]))")
                labels = [e["label"] for e in tl["entries"]]
                assert labels[0].startswith("Added to this wallet") or labels[0].startswith("Claimed")
                assert any(l.startswith("Claimed on your identity chain") for l in labels)
                assert any("code was requested" in l for l in labels) and any(l.startswith("Verified by Browser Test Verifier") for l in labels)
                assert any(l == "Attestation expires" for l in labels)
                times = [e["t"] for e in tl["entries"]]
                assert times == sorted(times)
                titles = [r["title"] for r in tl["raw"]]
                assert any(t.startswith("add_claim event") for t in titles) and any(t.startswith("attestation") for t in titles)
                raw_event = next(r for r in tl["raw"] if r["title"].startswith("add_claim"))
                from nodetide.core.identity import SigchainEvent
                assert raw_event["json"]["claim_id"] == claim_id
                # the hash shown and linked is the one Python computes for that very event
                assert raw_event["hash"] == SigchainEvent.from_dict(raw_event["json"]).event_hash()
                assert tl["explorer"]["event"] == f"{base}/explorer/#/event/{raw_event['hash']}"
                assert tl["explorer"]["identity"] == f"{base}/explorer/#/identity/{identity}"
                attestation_raw = next(r for r in tl["raw"] if r["title"].startswith("attestation"))
                assert "alice" not in json.dumps(attestation_raw["json"]).lower()  # the attestation does not carry the value
                async with http.get(f"{base}/api/explorer/events/{raw_event['hash']}") as r:
                    assert r.status == 200  # the explorer really knows the event the link points to
                    assert (await r.json())["event_type"] == "add_claim" if "event_type" in (await r.json()) else True

                # publishing the attestation makes it reachable in the explorer: about the holder, and issued by the verifier
                async with http.get(f"{base}/api/explorer/attestations?subject={identity}") as r:
                    assert (await r.json())["total"] == 0  # nothing public until the holder chooses
                await page.js("window.confirm = () => true")
                assert await attempt(f"await {wallet}.publish({json.dumps(claim_id)});") is None
                async with http.get(f"{base}/api/explorer/attestations?subject={identity}") as r:
                    listed = (await r.json())["items"]
                assert len(listed) == 1 and listed[0]["claim_type"] == "email" and "alice" not in json.dumps(listed).lower()
                issuer_hash = listed[0]["issuer"]
                async with http.get(f"{base}/api/explorer/attestations?issuer={issuer_hash}") as r:
                    assert (await r.json())["total"] == 1
                async with http.get(f"{base}/api/explorer/identities/{identity}") as r:
                    assert (await r.json())["counts"]["attestations_about"] == 1
                tl = await page.js(f"(async()=>{{await {wallet}.loadDetails({json.dumps(claim_id)}); return JSON.parse(JSON.stringify({wallet}.details[{json.dumps(claim_id)}]))}})()")
                assert any("published on the node" in e["label"] for e in tl["entries"])
                assert (await page.js(f"JSON.parse(JSON.stringify({wallet}.claims))"))[0]["published"] is True

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
            try:
                chrome.wait(timeout=15)  # the next test reuses the debugging port
            except subprocess.TimeoutExpired:
                chrome.kill()
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

                # forms ask for the identity password only when nothing else can supply it
                await load()
                assert await page.js("Alpine.store('protection').needsPassword") is True  # locked, no passkey (it was removed)
                assert await attempt(f"const c={wallet}; c.password='passkey-pass-12'; await c.unlock();") is None
                assert await page.js("Alpine.store('protection').needsPassword") is False   # unlocked wallet vouches for it
                assert "unlocked wallet" in await page.js("Alpine.store('protection').passwordHint")

                # an identity made WITH a passkey has no password at all
                assert await page.js(f"{comp('[x-data=identityManager]')}.webauthnSupported") is True
                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'no-password',
                    method:'webauthn',password:'',confirmPassword:'',distributionPoints:''}}; await m.createIdentity();}})()""")
                await asyncio.sleep(1.5)
                made = await page.js("JSON.parse(JSON.stringify(Alpine.store('identity').activeIdentity))")
                await load()
                assert await page.js("Alpine.store('protection').needsPassword") is False   # passkey identity, wallet locked
                assert "passkey" in await page.js("Alpine.store('protection').passwordHint")
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
            try:
                chrome.wait(timeout=15)  # the next test reuses the debugging port
            except subprocess.TimeoutExpired:
                chrome.kill()
        await node.close()


async def test_explorer_accepts_the_start_of_a_hash():
    from nodetide.core.identity import Identity

    node = TestServer(create_app(storage=Storage.memory(), web_root=str(WEB)))
    await node.start_server()
    base = f"http://127.0.0.1:{node.port}"
    chrome = None
    try:
        async with aiohttp.ClientSession() as http:
            person = Identity.create(name="Prefix Person")
            async with http.post(f"{base}/api/identities", json={"event": person.sigchain.to_list()[0]}) as r:
                assert r.status == 201
            full = person.identity_hash
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

                async def open_hash(fragment):
                    await page.call("Page.navigate", url=f"{base}/explorer/{fragment}")
                    await asyncio.sleep(2)
                    return await page.js("location.hash"), await page.js("document.body.innerText")

                where, text = await open_hash(f"#/identity/{full[:8]}")
                assert where == f"#/identity/{full}" and "Prefix Person" in text      # the short form finds the full page
                where, text = await open_hash(f"#/identity/{full}")
                assert "Prefix Person" in text and "Page not found" not in text
                where, text = await open_hash("#/identity/" + ("0" if not full.startswith("0") else "f") * 8)
                assert "No identity starts with" in text and "Page not found" not in text
    finally:
        if chrome:
            chrome.terminate()
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
        await node.close()


async def test_a_new_version_of_the_app_is_used_on_the_next_load():
    """The service worker must not keep serving an old copy of the app (it once did, until a second reload)."""
    import shutil

    web = tempfile.mkdtemp()
    shutil.copytree(WEB, web, dirs_exist_ok=True)
    node = TestServer(create_app(storage=Storage.memory(), web_root=web))
    await node.start_server()
    base = f"http://127.0.0.1:{node.port}"
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
                    await asyncio.sleep(2)

                await load()
                for _ in range(50):  # wait until the worker controls the page
                    if await page.js("!!navigator.serviceWorker.controller"):
                        break
                    await load()
                assert await page.js("!!navigator.serviceWorker.controller") is True
                assert await page.js("window.__marker") is None

                path = os.path.join(web, "js", "app.js")
                with open(path) as f:
                    source = f.read()
                with open(path, "w") as f:
                    f.write("window.__marker = 2;\n" + source)
                await load()
                assert await page.js("window.__marker") == 2  # the very next load, not the one after
    finally:
        if chrome:
            chrome.terminate()
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
        await node.close()


async def test_claims_left_over_from_an_earlier_chain_are_flagged_and_can_be_dropped():
    """A backup restored onto a node that does not have the claims (the identity was re-created there)."""
    nodes = [TestServer(create_app(storage=Storage.memory(), web_root=str(WEB))) for _ in range(2)]
    for n in nodes:
        await n.start_server()
    first, second = (f"http://127.0.0.1:{n.port}" for n in nodes)
    chrome = None
    try:
        async with aiohttp.ClientSession() as http:
            chrome = subprocess.Popen(
                [CHROME, "--headless=new", f"--remote-debugging-port={CDP_PORT + 2}", f"--user-data-dir={tempfile.mkdtemp()}",
                 "--no-first-run", "--disable-gpu", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tabs = None
            for _ in range(50):
                try:
                    async with http.get(f"http://127.0.0.1:{CDP_PORT + 2}/json") as r:
                        tabs = await r.json()
                        break
                except aiohttp.ClientError:
                    await asyncio.sleep(0.2)
            tab = next(t for t in tabs if t["type"] == "page")
            async with http.ws_connect(tab["webSocketDebuggerUrl"]) as ws:
                page = Page(ws)
                await page.call("Runtime.enable")
                await page.call("Page.enable")

                async def load(base):
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
                claims = lambda: page.js(f"JSON.parse(JSON.stringify({wallet}.claims))")  # noqa: E731

                # node one: an identity with a claim, and a backup of it
                await load(first)
                await page.js("""window.__files=[]; const orig=URL.createObjectURL;
                    URL.createObjectURL=(b)=>{ b.text().then(t=>window.__files.push(t)); return orig(b); };""", wait=False)
                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'leftover',
                    method:'password',password:'leftover-pass-1',confirmPassword:'leftover-pass-1',distributionPoints:''}};
                    await m.createIdentity();}})()""")
                await asyncio.sleep(1)
                identity = await page.js("Alpine.store('identity').activeHash")
                assert await attempt(f"const c={wallet}; c.password='leftover-pass-1'; await c.unlock();") is None
                assert await attempt(f"const c={wallet}; c.email='old@example.com'; await c.addEmail();") is None
                assert (await claims())[0]["orphan"] is False                       # on the chain it is made on
                assert await attempt(f"const c={comp('[x-data=protectionUI]')}; c.backup={{identityPassword:'leftover-pass-1',"
                                     "password:'correct horse battery',confirm:'correct horse battery'}; await c.makeBackup();") is None
                await asyncio.sleep(0.5)
                backup = (await page.js("window.__files"))[0]

                # node two knows the identity (restoring re-registers it) but never saw the claim
                await load(second)
                restored = await attempt(
                    f"const c={comp('[x-data=settingsManager]')}; c.restoreFile={{text:async()=>{json.dumps(backup)}}};"
                    "c.restorePassword='correct horse battery'; c.restoreLocalPassword='new-local-pass-9';"
                    "c.restoreLocalConfirmPassword='new-local-pass-9'; await c.restoreIdentity();")
                assert restored is None
                await page.js(f"Alpine.store('identity').setActive({json.dumps(identity)})")
                await asyncio.sleep(0.5)
                assert await attempt(f"const c={wallet}; c.password='new-local-pass-9'; await c.unlock();") is None
                left = await claims()
                assert len(left) == 1 and left[0]["orphan"] is True and left[0]["codeable"] is False   # flagged, and nothing can be done with it

                assert "left over" in await attempt(f"await {wallet}.verify({json.dumps(left[0]['id'])});")
                await page.js("window.confirm = () => true")  # (a confirm dialog would block a headless page for good)
                assert "not on your identity chain" in await attempt(f"await {wallet}.renounce({json.dumps(left[0]['id'])});")
                assert await attempt(f"await {wallet}.forget({json.dumps(left[0]['id'])});") is None
                assert await claims() == []

                # and the same address can now be claimed afresh, properly on this chain
                assert await attempt(f"const c={wallet}; c.email='old@example.com'; await c.addEmail();") is None
                fresh = await claims()
                assert len(fresh) == 1 and fresh[0]["orphan"] is False and fresh[0]["id"] != left[0]["id"]
                assert "on your identity chain" in await attempt(f"await {wallet}.forget({json.dumps(fresh[0]['id'])});")
    finally:
        if chrome:
            chrome.terminate()
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
        for n in nodes:
            await n.close()
