"""The browser makes the DNS state record, and Python's verifier accepts what it made.

Same requirements as the other browser tests (Chrome, internet for the CDN scripts):
    NODETIDE_BROWSER_TESTS=1 pytest tests/test_web_state_record_browser.py
"""

import asyncio
import json
import subprocess
import tempfile
import time

import aiohttp
import pytest
from aiohttp.test_utils import TestServer

from nodetide.api.app import create_app
from nodetide.core.auth import AuthRequest, verify_assertion_with_state
from nodetide.core.dns_source import record_name
from nodetide.core.state import StateError, decode, verify_state
from nodetide.core.storage import Storage
from tests.test_web_protection_browser import CDP_PORT, CHROME, WEB, Page, comp, pytestmark  # noqa: F401


async def test_the_identity_tab_makes_a_record_python_accepts():
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
                await page.call("Page.navigate", url=base + "/")
                for _ in range(100):
                    if await page.js("!!(window.Alpine && Alpine.store('wallet') && window.NodetideState)", wait=False):
                        break
                    await asyncio.sleep(0.2)
                await asyncio.sleep(0.5)

                async def attempt(expr):
                    await page.js("Alpine.store('app').error=null")
                    await page.js(f"(async()=>{{{expr}}})()")
                    return await page.js("Alpine.store('app').error")

                # a name with a non-ASCII letter: the record must be signed over what Python reproduces
                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'Алекс',
                    method:'password',password:'record-pass-12',confirmPassword:'record-pass-12',distributionPoints:'dns:example.org'}};
                    await m.createIdentity();}})()""")
                await asyncio.sleep(1)
                identity = await page.js("Alpine.store('identity').activeHash")
                await page.js("Alpine.store('app').setView('identity')")
                card = comp("[x-data=stateRecordUI]")
                await asyncio.sleep(0.8)
                await page.js(f"{comp('[x-data=identityDetail]')}.setTab('publish')")      # the record is made on the Publish tab
                await asyncio.sleep(0.4)

                # the card is there; while the wallet is locked nothing is made
                assert await page.js("""(()=>{const e=[...document.querySelectorAll('.card-title')]
                    .find(x=>x.textContent.includes('DNS state record')); return !!e && e.offsetParent!==null})()""")
                assert "Unlock the wallet" in await attempt(f"const c={card}; c.domain='example.org'; await c.generate();")

                wallet = comp("[x-data=walletUI]")
                assert await attempt(f"const c={wallet}; c.password='record-pass-12'; await c.unlock();") is None

                # the domain is taken from the identity's dns: distribution point; bad domains are refused
                await page.js(f"{card}.prepare()")
                await asyncio.sleep(0.5)
                assert await page.js(f"{card}.domain") == "example.org"
                for bad in ["localhost", "192.168.1.5", "nas.local", "not a domain", "example"]:
                    err = await attempt(f"const c={card}; c.domain={json.dumps(bad)}; await c.generate();")
                    assert err and "domain" in err.lower(), bad

                # the record
                assert await attempt(f"const c={card}; c.domain='Example.ORG'; c.days=7; await c.generate();") is None
                result = await page.js(f"JSON.parse(JSON.stringify({card}.result))")
                assert result["domain"] == "example.org" and result["name"] == record_name("example.org", identity)
                assert result["hasPoint"] is True and result["size"] == len(result["value"]) < 3800
                assert result["zone"].startswith(f"{result['name']}. 300 IN TXT \"nt1;") and len(result["devices"]) == 1
                print("browser record:", result["size"], "characters,", len(result["devices"]), "device")

                # Python verifies it: master lineage, signature, identity, and the device the web client signs in with
                state = verify_state(decode(result["value"]), expect_identity=identity)
                async with http.get(f"{base}/api/identities/{identity}") as r:
                    info = await r.json()
                from nodetide.core.identity import Sigchain
                chain = Sigchain.from_list(info["sigchain"])
                assert state.head_hash == chain.head_hash and state.length == len(chain.events)
                assert state.master == info["master_pubkey"]
                assert {d.pubkey for d in state.devices} == {d["pubkey"] for d in info["devices"] if d["pubkey"] != info["master_pubkey"]}
                assert state.expires - state.timestamp == 7 * 86400 and abs(state.timestamp - time.time()) < 120
    finally:
        if chrome:
            chrome.terminate()
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
        await node.close()
