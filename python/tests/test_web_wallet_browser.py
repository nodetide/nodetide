"""The browser wallet: claims, email verification against a real verifier service on another origin, persistence and backup.

Same requirements as test_web_protection_browser (Chrome, internet for the CDN scripts):
    NODETIDE_BROWSER_TESTS=1 pytest tests/test_web_wallet_browser.py
"""

import asyncio
import json
import os
import re
import subprocess
import tempfile

import aiohttp
from aiohttp.test_utils import TestServer

from nodetide.api.app import create_app
from nodetide.core.storage import Storage
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
    node = TestServer(create_app(storage=Storage.memory(), web_root=str(WEB)))
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
