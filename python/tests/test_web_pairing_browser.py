"""Add a device by QR: the web wallet shows the invitation, a (simulated) phone answers through the node, the owner confirms.

Same requirements as the other browser tests (Chrome, internet for the CDN scripts):
    NODETIDE_BROWSER_TESTS=1 pytest tests/test_web_pairing_browser.py
"""

import asyncio
import base64
import hashlib
import json
import subprocess
import tempfile
from urllib.parse import parse_qs, urlsplit

import aiohttp
from aiohttp.test_utils import TestServer

from nodetide.api.app import create_app
from nodetide.core.crypto import EncryptionPublicKey, KeyPair
from nodetide.core.identity import DeviceCapability, Sigchain
from nodetide.core.storage import Storage
from tests.test_web_protection_browser import CDP_PORT, CHROME, WEB, Page, comp, pytestmark  # noqa: F401

ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def slot_name(code):
    return hashlib.sha256(b"nodetide-pairing:" + code.encode()).hexdigest()


def fingerprint(pubkey_hex):
    d = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:12]
    return "-".join(d[i:i + 4] for i in range(0, 12, 4))


async def test_a_phone_is_added_by_scanning_the_wallets_qr():
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
                    if await page.js("!!(window.Alpine && Alpine.store('wallet'))", wait=False):
                        break
                    await asyncio.sleep(0.2)
                await asyncio.sleep(0.5)

                await page.js(f"""(async()=>{{const m={comp('[x-data=identityManager]')}; m.createForm={{name:'Pairing',
                    method:'password',password:'pair-pass-12',confirmPassword:'pair-pass-12',distributionPoints:''}};
                    await m.createIdentity();}})()""")
                await asyncio.sleep(1)
                identity = await page.js("Alpine.store('identity').activeHash")
                await page.js("Alpine.store('app').setView('identity')")
                await asyncio.sleep(0.8)
                detail = comp("[x-data=identityDetail]")
                await page.js(f"{detail}.setTab('devices')")
                await asyncio.sleep(0.4)
                pair = comp("[x-data=pairDeviceUI]")

                # locked: nothing starts
                await page.js(f"(async()=>{{await {pair}.start()}})()")
                assert await page.js(f"{pair}.step") == "idle" and "Unlock" in await page.js(f"{pair}.error")

                wallet = comp("[x-data=walletUI]")
                await page.js(f"(async()=>{{const c={wallet}; c.password='pair-pass-12'; await c.unlock();}})()")
                await asyncio.sleep(1)
                # a claim, so the chain has content the new control event has to commit to
                await page.js(f"(async()=>{{const c={wallet}; c.email='pair@example.com'; await c.addEmail();}})()")
                await asyncio.sleep(1)

                await page.js(f"(async()=>{{await {pair}.start()}})()")
                assert await page.js(f"{pair}.step") == "waiting"
                invite = await page.js(f"{pair}.invite")
                code = await page.js(f"{pair}.code")
                assert len(code) == 10 and all(c in ALPHABET for c in code)
                u = urlsplit(invite)
                q = parse_qs(u.query)
                assert (u.scheme, u.netloc, u.path) == ("nodetide", "pair", "") and q["c"] == [code] and q["i"] == [identity] and q["n"] == [base]
                assert await page.js("!!document.querySelector('[x-data=pairDeviceUI] canvas')")        # the QR is drawn

                # the phone: its own keys, opens the slot named by the hash of the code (what it learned from the QR)
                phone = KeyPair.generate()
                async with http.post(f"{base}/api/pairing", json={"slot": slot_name(code), "request": {
                        "device_pubkey": phone.verify_key.to_hex(), "device_encryption_pubkey": phone.public_encryption_key.to_hex(),
                        "label": "Test phone"}}) as r:
                    assert r.status == 201

                for _ in range(30):
                    if await page.js(f"{pair}.step") == "confirm":
                        break
                    await asyncio.sleep(0.4)
                assert await page.js(f"{pair}.step") == "confirm"
                assert await page.js(f"{pair}.fingerprint") == fingerprint(phone.verify_key.to_hex())
                assert (await page.js(f"{pair}.device.label")) == "Test phone"

                # nothing is authorized until the owner confirms
                async with http.get(f"{base}/api/identities/{identity}") as r:
                    assert len((await r.json())["devices"]) == 2           # the master key and this browser
                await page.js(f"(async()=>{{await {pair}.approve()}})()")
                await asyncio.sleep(1.2)
                assert await page.js(f"{pair}.step") == "done" and not await page.js(f"{pair}.error")

                async with http.get(f"{base}/api/identities/{identity}") as r:
                    info = await r.json()
                chain = Sigchain.from_list(info["sigchain"])
                assert info["verified"] is True and chain.verify() == (True, None)
                mine = next(d for d in chain.get_active_devices() if d.pubkey == phone.verify_key.to_hex())
                assert mine.label == "Test phone" and mine.encryption_pubkey == phone.public_encryption_key.to_hex()
                assert {DeviceCapability.AUTHENTICATE.value, DeviceCapability.MANAGE_CLAIMS.value} <= set(mine.capabilities)
                event = [e for e in chain.events if e.type.value == "add_device"][-1]
                assert event.content and event.content["count"] == 1                          # it commits to the claim

                # the sealed answer opens with the phone's key and carries the chain, from a device of that chain
                async with http.get(f"{base}/api/pairing/{slot_name(code)}") as r:
                    answer = (await r.json())["response"]
                sender = EncryptionPublicKey.from_hex(answer["from_encryption_pubkey"])
                payload = json.loads(phone.encryption_key.decrypt(base64.b64decode(answer["sealed"]), sender))
                assert Sigchain.from_list(payload["sigchain"]).head_hash == chain.head_hash
                assert any(d.encryption_pubkey == answer["from_encryption_pubkey"] for d in chain.get_active_devices())

                # the devices tab lists the new device
                await page.js(f"{detail}.lastLoadedHash=null; {detail}.load()")
                await asyncio.sleep(1)
                assert await page.js(f"{detail}.devices.length") == 3

                # a second code is a new slot; cancelling forgets it
                await page.js(f"(async()=>{{{pair}.cancel(); await {pair}.start()}})()")
                assert await page.js(f"{pair}.code") != code and await page.js(f"{pair}.step") == "waiting"
                await page.js(f"{pair}.cancel()")
                assert await page.js(f"{pair}.step") == "idle"
    finally:
        if chrome:
            chrome.terminate()
            try:
                chrome.wait(timeout=15)
            except subprocess.TimeoutExpired:
                chrome.kill()
        await node.close()
