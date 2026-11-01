"""My Identity is split into sub-tabs; the distribution points can be edited (once more) with the wallet unlocked.

Same requirements as the other browser tests (Chrome, internet for the CDN scripts):
    NODETIDE_BROWSER_TESTS=1 pytest tests/test_web_identity_tabs_browser.py
"""

import asyncio
import json
import subprocess
import tempfile

import aiohttp
from aiohttp.test_utils import TestServer

from nodetide.api.app import create_app
from nodetide.core.identity import Sigchain
from nodetide.core.storage import Storage
from tests.test_web_protection_browser import CDP_PORT, CHROME, WEB, Page, comp, pytestmark  # noqa: F401

PANELS = ["overview", "claims", "devices", "publish", "orgs", "history"]


async def test_sub_tabs_and_editing_distribution_points():
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
                        if await page.js("!!(window.Alpine && Alpine.store('wallet') && window.NodetideState)", wait=False):
                            break
                        await asyncio.sleep(0.2)
                    await asyncio.sleep(0.8)

                async def attempt(expr):
                    await page.js("Alpine.store('app').error=null")
                    await page.js(f"(async()=>{{{expr}}})()")
                    return await page.js("Alpine.store('app').error")

                detail = comp("[x-data=identityDetail]")

                async def visible_panels():
                    return await page.js(f"""[...document.querySelectorAll('[role=tabpanel]')].filter(p=>p.offsetParent!==null)
                        .map(p=>p.getAttribute('x-show').match(/'(\\w+)'/)[1])""")

                await load()
                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'Tabs',
                    method:'password',password:'tabs-pass-12',confirmPassword:'tabs-pass-12',distributionPoints:''}};
                    await m.createIdentity();}})()""")
                await asyncio.sleep(1)
                identity = await page.js("Alpine.store('identity').activeHash")
                await page.js("Alpine.store('app').setView('identity')")
                await asyncio.sleep(0.8)

                # six tabs, one panel at a time, starting on the overview
                labels = await page.js("[...document.querySelectorAll('.subtabs button')].map(b=>b.textContent.trim())")
                assert labels == ["Overview", "Claims", "Devices & recovery", "Publish", "Organizations", "History"]
                assert await visible_panels() == ["overview"]
                for t in PANELS:
                    await page.js(f"[...document.querySelectorAll('.subtabs button')][{PANELS.index(t)}].click()")
                    await asyncio.sleep(0.2)
                    assert await visible_panels() == [t], t
                # the overview holds the identity's facts and QR, not the whole page
                await page.js(f"{detail}.setTab('overview')")
                titles = await page.js("[...[...document.querySelectorAll('[role=tabpanel]')].find(p=>p.offsetParent!==null).querySelectorAll('.card-title')].map(c=>c.textContent.trim())")
                assert titles == ["Identity Info", "Share Identity", "At a glance"]
                # an unknown tab is ignored; the chosen tab survives a reload
                await page.js(f"{detail}.setTab('nonsense')")
                assert await page.js(f"{detail}.tab") == "overview"
                await page.js(f"{detail}.setTab('publish')")
                await load()
                await page.js("Alpine.store('app').setView('identity')")
                await asyncio.sleep(0.8)
                assert await visible_panels() == ["publish"]

                # unlocking from the overview takes you to the claims (that is what unlocking used to reveal); the overview has a summary
                await page.js(f"{detail}.setTab('overview')")
                await asyncio.sleep(0.3)
                summary = await page.js("[...document.querySelectorAll('.glance')][0].innerText")
                assert "unlock the wallet to see them" in summary and "events" in summary and "not set up" in summary
                await page.js(f"{detail}.setTab('publish')")

                # Edit with the wallet locked says what to do instead of nothing
                await page.js("Alpine.store('app').error=null; [...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Edit').click()")
                await asyncio.sleep(0.3)
                assert await page.js(f"{detail}.showDistributionModal") is False
                assert "Unlock the wallet" in await page.js("Alpine.store('app').error")

                # unlock from the bar (the real form), then Edit opens the dialog, and it is visible
                assert await page.js("!!document.querySelector('.wallet-bar input[type=password]')")
                await page.js("""(()=>{const i=document.querySelector('.wallet-bar input[type=password]'); i.value='tabs-pass-12';
                    i.dispatchEvent(new Event('input')); [...document.querySelectorAll('.wallet-bar button')].find(b=>b.textContent.trim()==='Unlock').click()})()""")
                for _ in range(30):
                    if await page.js("Alpine.store('wallet').unlocked"):
                        break
                    await asyncio.sleep(0.2)
                assert await page.js("Alpine.store('wallet').unlocked") is True
                assert "Wallet unlocked" in await page.js("document.querySelector('.wallet-bar').innerText")
                assert await page.js(f"{detail}.tab") == "publish"                       # unlocking elsewhere keeps you where you are
                await page.js("[...document.querySelectorAll('.wallet-bar button')].find(b=>b.textContent.trim()==='Lock').click()")
                await asyncio.sleep(0.3)
                await page.js(f"{detail}.setTab('overview')")
                await asyncio.sleep(0.3)
                await page.js("""(()=>{const i=document.querySelector('.wallet-bar input[type=password]'); i.value='tabs-pass-12';
                    i.dispatchEvent(new Event('input')); [...document.querySelectorAll('.wallet-bar button')].find(b=>b.textContent.trim()==='Unlock').click()})()""")
                for _ in range(30):
                    if await page.js(f"{detail}.tab") == "claims":
                        break
                    await asyncio.sleep(0.2)
                assert await page.js(f"{detail}.tab") == "claims" and await visible_panels() == ["claims"]
                await page.js(f"{detail}.setTab('publish')")
                # a claim first, so the chain has content the new control event must commit to
                wallet = comp("[x-data=walletUI]")
                assert await attempt(f"const c={wallet}; c.email='tabs@example.com'; await c.addEmail();") is None
                await page.js("Alpine.store('app').error=null; [...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='Edit').click()")
                await asyncio.sleep(0.3)
                assert await page.js(f"{detail}.showDistributionModal") is True
                assert await page.js("(()=>{const m=document.querySelector('.modal-backdrop[x-show=showDistributionModal]'); return getComputedStyle(m).display!=='none'})()")

                # doubtful points are refused on the spot, nothing is signed
                for bad in ["mailto:a@b.example?cc=v@c.example", "dns:192.168.1.5", "ftp host", "mailto:x@y"]:
                    await page.js(f"{detail}.editDistributionPoints={json.dumps(bad)}; {detail}.saveDistributionPoints()")
                    await asyncio.sleep(0.2)
                    assert await page.js(f"{detail}.distributionError"), bad
                async with http.get(f"{base}/api/identities/{identity}/sigchain") as r:
                    events = (await r.json())["events"]
                assert not [e for e in events if e["type"] == "set_distribution"]

                # good ones: signed over the last CONTROL event, committing to the claim; the chain still verifies in Python
                points = ["https://relay.example.org", "mailto:chains@node.example", "dns:example.org", "dtn://node.local:4556"]
                await page.js(f"{detail}.editDistributionPoints={json.dumps(chr(10).join(points))}; {detail}.saveDistributionPoints()")
                await asyncio.sleep(1.2)
                assert await page.js(f"{detail}.showDistributionModal") is False and await page.js(f"{detail}.distributionError") == ""
                async with http.get(f"{base}/api/identities/{identity}") as r:
                    info = await r.json()
                chain = Sigchain.from_list(info["sigchain"])
                assert info["verified"] is True and chain.verify() == (True, None)
                event = [e for e in chain.events if e.type.value == "set_distribution"][0]
                assert event.distribution_points == points and event.content == {"count": 1, "root": event.content["root"]}
                assert await page.js(f"JSON.parse(JSON.stringify({detail}.distributionPoints))") == points

                # the DNS card on the same tab picks up the dns: point
                await page.js("document.querySelector('[x-data=stateRecordUI]') && Alpine.$data(document.querySelector('[x-data=stateRecordUI]')).prepare()")
                await asyncio.sleep(0.8)
                assert await page.js(f"{comp('[x-data=stateRecordUI]')}.domain") == "example.org"

                # editing again replaces them (a second set_distribution on top of the first)
                await page.js(f"{detail}.openDistributionModal(); {detail}.editDistributionPoints='https://other.example.org'; {detail}.saveDistributionPoints()")
                await asyncio.sleep(1.2)
                async with http.get(f"{base}/api/identities/{identity}") as r:
                    info = await r.json()
                assert Sigchain.from_list(info["sigchain"]).verify() == (True, None)
                assert await page.js(f"JSON.parse(JSON.stringify({detail}.distributionPoints))") == ["https://other.example.org"]
    finally:
        if chrome:
            chrome.terminate()
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
        await node.close()
