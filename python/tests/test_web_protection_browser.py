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
from nodetide.core.identity import Identity
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
            trustees = []
            for _ in range(3):
                i = Identity.create(name="trustee")
                async with http.post(f"{base}/api/identities", json={"event": i.sigchain.to_list()[0]}) as r:
                    assert r.status in (200, 201)
                trustees.append(i.identity_hash)

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
    finally:
        if chrome:
            chrome.terminate()
        await server.close()
