"""The web client in a real (headless) Chrome: banner until backup + social recovery, restore after losing storage.

Needs Chrome and internet access (the page loads Alpine and tweetnacl from a CDN), so it runs only when asked:
    NODETIDE_BROWSER_TESTS=1 pytest tests/test_web_protection_browser.py
"""

import asyncio
import itertools
import json
import os
import subprocess
import tempfile
from pathlib import Path

import aiohttp
import pytest
from aiohttp.test_utils import TestServer

from nodetide.api.app import create_app
from nodetide.core.crypto import KeyPair
from nodetide.core.identity import Identity, Sigchain, SocialRecoveryEvent, sign_recovery
from nodetide.core.storage import Storage as VerifierStorage
from nodetide.verifiers.issuer import IssuerNotReady, founding_request, load_owned
from nodetide.core.storage import Storage

CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
WEB = Path(__file__).resolve().parents[2] / "web"
CDP_PORT = 9333

pytestmark = pytest.mark.skipif(
    os.environ.get("NODETIDE_BROWSER_TESTS") != "1" or not Path(CHROME).exists(),
    reason="set NODETIDE_BROWSER_TESTS=1 and have Chrome installed",
)


class Page:
    def __init__(self, ws):
        self.ws, self.ids = ws, itertools.count(1)

    async def call(self, method, **params):
        i = next(self.ids)
        await self.ws.send_json({"id": i, "method": method, "params": params})
        async for msg in self.ws:
            d = json.loads(msg.data)
            if d.get("id") == i:
                if "error" in d:
                    raise RuntimeError(d["error"])
                return d["result"]

    async def js(self, expr, wait=True):
        r = await self.call("Runtime.evaluate", expression=expr, awaitPromise=wait, returnByValue=True)
        if "exceptionDetails" in r:
            raise RuntimeError(json.dumps(r["exceptionDetails"])[:600])
        return r["result"].get("value")


def comp(selector):
    return f"Alpine.$data(document.querySelector('{selector}'))"


async def test_banner_backup_recovery_and_restore():
    server = TestServer(create_app(storage=Storage.memory(), web_root=str(WEB)))
    await server.start_server()
    base = f"http://127.0.0.1:{server.port}"
    chrome = None
    try:
        async with aiohttp.ClientSession() as http:
            trustees, people = [], []
            for _ in range(3):
                i = Identity.create(name="trustee")
                async with http.post(f"{base}/api/identities", json={"event": i.sigchain.to_list()[0]}) as r:
                    assert r.status in (200, 201)
                trustees.append(i.identity_hash)
                people.append(i)

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
                        if await page.js("!!(window.Alpine && Alpine.store('protection'))", wait=False):
                            break
                        await asyncio.sleep(0.2)
                    await asyncio.sleep(0.5)

                async def attempt(expr):
                    """Run a component action and return the error it showed, if any."""
                    await page.js("Alpine.store('app').error=null")
                    await page.js(f"(async()=>{{{expr}}})()")
                    return await page.js("Alpine.store('app').error")

                await load()
                await page.js("""window.__files=[]; const orig=URL.createObjectURL;
                    URL.createObjectURL=(b)=>{ b.text().then(t=>window.__files.push(t)); return orig(b); };""", wait=False)

                assert await page.js("Alpine.store('protection').show") is False  # nothing to protect yet
                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'zqunique-name',
                    method:'password',password:'identity-pass-1',confirmPassword:'identity-pass-1',distributionPoints:''}};
                    await m.createIdentity();}})()""")
                await asyncio.sleep(1)
                await page.js("Alpine.store('protection').refresh()")
                identity = await page.js("Alpine.store('identity').activeHash")
                assert await page.js("Alpine.store('protection').show") is True
                assert await page.js("(()=>{const e=document.querySelector('.protection-banner');return !!e && e.offsetParent!==null})()")

                def backup(pw, confirm, identity_pw="identity-pass-1"):
                    return attempt(f"const c={comp('[x-data=protectionUI]')}; c.backup={{identityPassword:{json.dumps(identity_pw)},"
                                   f"password:{json.dumps(pw)},confirm:{json.dumps(confirm)}}}; await c.makeBackup();")

                assert "at least 12" in await backup("short", "short")
                assert "differ" in await backup("correct horse battery", "correct horse batterY")
                assert "Invalid identity password" in await backup("correct horse battery", "correct horse battery", "nope")
                assert await page.js("Alpine.store('protection').backupDone") is False

                assert await backup("correct horse battery", "correct horse battery") is None
                await asyncio.sleep(0.5)
                files = await page.js("window.__files")
                saved = json.loads(files[0])
                assert saved["encrypted"]["kdf_iterations"] == 1_000_000 and saved["holds_master_key"] is True
                assert "secretKey" not in files[0] and "zqunique" not in files[0]
                assert await page.js("Alpine.store('protection').backupDone") is True
                assert await page.js("Alpine.store('protection').show") is True  # recovery still missing

                def recovery(text, threshold):
                    return attempt(f"const c={comp('[x-data=protectionUI]')}; c.recovery={{identityPassword:'identity-pass-1',"
                                   f"trustees:{json.dumps(text)},threshold:{json.dumps(threshold)}}}; await c.setRecovery();")

                assert "at least 3" in await recovery("\n".join(trustees[:2]), 2)
                assert "does not know" in await recovery("\n".join([*trustees[:2], "ab" * 32]), 2)
                assert "between 2 and 3" in await recovery("\n".join(trustees), 4)
                assert await recovery("\n".join(trustees), 2) is None
                await asyncio.sleep(0.8)
                shown = await (await http.get(f"{base}/api/identities/{identity}")).json()
                assert shown["recovery"]["primary_trustees"] == trustees and shown["recovery"]["primary_threshold"] == 2
                assert await page.js("Alpine.store('protection').show") is False  # both done: the banner goes

                # the browser loses its storage; the backup brings the identity back, the node's chain untouched
                await page.js("localStorage.clear()", wait=False)
                await load()
                assert await page.js("Alpine.store('identity').identities.length") == 0

                def restore(password):
                    return attempt(f"const c={comp('[x-data=settingsManager]')}; c.restoreFile={{text:async()=>{json.dumps(files[0])}}};"
                                   f"c.restorePassword={json.dumps(password)}; c.restoreLocalPassword='new-local-pass-9';"
                                   "c.restoreLocalConfirmPassword='new-local-pass-9'; await c.restoreIdentity();")

                assert "Invalid password" in await restore("wrong wrong wrong")
                assert await page.js("Alpine.store('identity').identities.length") == 0
                assert await restore("correct horse battery") is None
                chain = await (await http.get(f"{base}/api/identities/{identity}/sigchain")).json()
                assert chain["length"] == 3  # genesis, add_device, set_recovery: restoring did not truncate it
                await page.js(f"Alpine.store('identity').setActive({json.dumps(identity)})")
                await asyncio.sleep(1)
                assert await page.js("Alpine.store('protection').backupDone") is True
                assert await page.js("Alpine.store('protection').recoveryDone") is True
                assert await page.js("Alpine.store('protection').show") is False
                # the restored master key works, under the new local password only
                assert await backup("another strong passphrase", "another strong passphrase", "new-local-pass-9") is None
                assert "Invalid identity password" in await backup("another strong passphrase", "another strong passphrase")

                # --- social recovery: the keys are lost again; two of the three trustees restore control -----------------
                await page.js("localStorage.clear()", wait=False)
                await load()
                lost = comp('[x-data=protectionUI]')
                assert "at least 8" in await attempt(f"const c={lost}; c.lost={{identityHash:{json.dumps(identity)},password:'x'}}; await c.askForRecovery();")
                assert "64 hex" in await attempt(f"const c={lost}; c.lost={{identityHash:'nope',password:'new-local-pass-9'}}; await c.askForRecovery();")
                assert await attempt(f"const c={lost}; c.lost={{identityHash:{json.dumps(identity)},password:'new-local-pass-9',code:'',waiting:false,collected:0,threshold:0}}; await c.askForRecovery();") is None
                code = await page.js(f"{lost}.lost.code")
                rid = code.split(":")[1]
                async with http.get(f"{base}/api/identities/{identity}/recovery/{rid}") as r:
                    st = await r.json()
                assert st["status"] == "pending" and st["threshold"] == 2
                assert await attempt(f"await {lost}.checkRecovery();") is None  # nobody has signed yet: it just reports that
                for who in (people[0], people[2]):
                    rec = sign_recovery(who.identity_hash, who.local_keypair, who.sigchain.head_hash, identity, st["prev"],
                                        st["new_master_pubkey"], st["new_encryption_pubkey"])
                    async with http.post(f"{base}/api/identities/{identity}/recovery/{rid}/sign", json={"record": rec}) as r:
                        assert r.status == 200, await r.text()
                assert await attempt(f"await {lost}.checkRecovery();") is None
                await asyncio.sleep(0.5)
                async with http.get(f"{base}/api/identities/{identity}/sigchain") as r:
                    chain = await r.json()
                assert chain["length"] == 5  # genesis, add_device, set_recovery, social_recovery, add_device
                async with http.get(f"{base}/api/identities/{identity}") as r:
                    info = await r.json()
                assert info["verified"] is True
                assert await page.js("Alpine.store('identity').identities.length") == 1
                held = await page.js("Alpine.store('identity').identities[0].masterSigningPubkey")
                assert info["master_pubkey"] == held == st["new_master_pubkey"]
                await page.js(f"Alpine.store('identity').setActive({json.dumps(identity)})")
                await asyncio.sleep(1)
                assert await page.js("Alpine.store('protection').backupDone") is False  # a new key needs a new backup
                assert await page.js("Alpine.store('protection').recoveryDone") is True

                # --- the browser as a trustee: its signature must satisfy the node (cross-language check) -----------------
                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'trustee-in-browser',
                    method:'password',password:'trustee-pass-12',confirmPassword:'trustee-pass-12',distributionPoints:''}};
                    await m.createIdentity();}})()""")
                await asyncio.sleep(1)
                browser_trustee = await page.js("Alpine.store('identity').activeHash")
                assert browser_trustee != identity
                friend = Identity.create(name="friend")
                async with http.post(f"{base}/api/identities", json={"event": friend.sigchain.to_list()[0]}) as r:
                    assert r.status == 201
                friend.set_recovery([browser_trustee, people[0].identity_hash, people[1].identity_hash], 2)
                async with http.post(f"{base}/api/identities/{friend.identity_hash}/events", json={"event": friend.sigchain.to_list()[1]}) as r:
                    assert r.status == 201, await r.text()
                new = KeyPair.generate()
                async with http.post(f"{base}/api/identities/{friend.identity_hash}/recovery/initiate", json={
                        "new_pubkey": new.verify_key.to_hex(), "new_encryption_pubkey": new.public_encryption_key.to_hex()}) as r:
                    started = await r.json()
                fcode = f"{friend.identity_hash}:{started['recovery_id']}"
                assert await attempt(f"const c={lost}; c.help={{code:{json.dumps(fcode)},password:'wrong-pass-123',seen:null}}; await c.lookUp(); await c.vouch();") is not None
                assert await attempt(f"const c={lost}; c.help={{code:{json.dumps(fcode)},password:'trustee-pass-12',seen:null}}; await c.lookUp(); await c.vouch();") is None
                rec = sign_recovery(people[0].identity_hash, people[0].local_keypair, people[0].sigchain.head_hash, friend.identity_hash,
                                    started["prev"], new.verify_key.to_hex(), new.public_encryption_key.to_hex())
                async with http.post(f"{base}/api/identities/{friend.identity_hash}/recovery/{started['recovery_id']}/sign", json={"record": rec}) as r:
                    done = await r.json()
                assert done["status"] == "complete"
                ev = SocialRecoveryEvent(type=None, timestamp=1, prev=started["prev"], signature="", signed_by=new.verify_key.to_hex(),
                                         new_pubkey=new.verify_key.to_hex(), new_encryption_pubkey=new.public_encryption_key.to_hex(),
                                         recovery_signatures=[x["record"] for x in done["signatures"]])
                ev.signature = new.sign_hex(json.dumps(ev.signable_dict(), sort_keys=True, separators=(",", ":")).encode())
                async with http.post(f"{base}/api/identities/{friend.identity_hash}/events", json={"event": ev.to_dict()}) as r:
                    assert r.status == 201, await r.text()  # the browser's signature convinced the node

                # --- an organization owned by this browser identity: the verifier's key founds nothing without the owner -------
                verifier_db = VerifierStorage.memory()
                founding = founding_request(verifier_db, "Test verifier", browser_trustee)

                def approve_form(request, password="trustee-pass-12"):
                    form = {"password": password, "request": request, "result": None}
                    return attempt(f"const c={lost}; c.org={json.dumps(form)}; await c.approveOrganization();")

                assert "Invalid identity password" in await approve_form(json.dumps(founding), "wrong")
                assert "not the founding" in await approve_form(json.dumps({"type": "genesis", "identity_type": "personal"}))
                forged = json.loads(json.dumps(founding)); forged["genesis"]["name"] = "Evil"
                assert "signature is invalid" in await approve_form(json.dumps(forged))
                outsider = json.loads(json.dumps(founding_request(VerifierStorage.memory(), "Other", people[0].identity_hash)))
                assert "not one of this organization" in await approve_form(json.dumps(outsider))
                with pytest.raises(IssuerNotReady, match="ISSUER_ORG"):
                    await asyncio.to_thread(load_owned, verifier_db, "Test verifier", None, base, browser_trustee)

                assert await approve_form(json.dumps(founding)) is None
                org_hash = await page.js(f"{lost}.org.result.orgHash")
                async with http.get(f"{base}/api/identities/{org_hash}") as r:
                    org_info = await r.json()
                assert org_info["type"] == "organization" and org_info["verified"] is True

                # the verifier, given the hash, has its organization authorize the signing key by itself
                issuer = await asyncio.to_thread(load_owned, verifier_db, "Test verifier", org_hash, base, browser_trustee)
                assert issuer.identity_hash == org_hash
                async with http.get(f"{base}/api/identities/{org_hash}") as r:
                    org_info = await r.json()
                assert org_info["verified"] is True and len(org_info["devices"]) == 2
    finally:
        if chrome:
            chrome.terminate()
        await server.close()
