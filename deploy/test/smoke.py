#!/usr/bin/env python3
"""End-to-end check of a running test stack, walking the flow the way a person would.

    smoke.py prepare     make a synthetic "eID" CA so the legal-name path can be tested without a card
    smoke.py run         sign in through the standard OIDC client twice (sharing claims, then not)

Needs the repository's Python environment (nodetide and aiohttp). `run` reads .env for the URLs
and the wallet password. Against a remote server the URLs resolve normally; for *.localtest.me
they are pinned to 127.0.0.1 so no DNS is needed.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp.abc import AbstractResolver

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SMOKE = HERE / ".smoke"
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "python" / "src"))

EMAIL = "smoke@example.com"
GIVEN, FAMILY = "Maria", "Ivanova"


def load_env() -> dict[str, str]:
    env = {}
    for line in (HERE / ".env").read_text().splitlines():
        if line.strip() and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


class PinLocal(AbstractResolver):
    """Resolve the stack's *.localtest.me names to this machine without DNS."""

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host.endswith("localtest.me"):
            return [{"hostname": host, "host": "127.0.0.1", "port": port, "family": socket.AF_INET, "proto": 0, "flags": 0}]
        return await aiohttp.ThreadedResolver().resolve(host, port, family)

    async def close(self):
        pass


class Check:
    def __init__(self) -> None:
        self.failed = 0

    def ok(self, label: str, detail: str = "") -> None:
        print(f"  ok    {label}" + (f"  ({detail})" if detail else ""), flush=True)

    def fail(self, label: str, detail: str = "") -> None:
        self.failed += 1
        print(f"  FAIL  {label}" + (f"  ({detail})" if detail else ""), flush=True)

    def expect(self, condition: bool, label: str, detail: str = "") -> bool:
        (self.ok if condition else self.fail)(label, detail)
        return condition


# --- prepare ----------------------------------------------------------------------------------------


def prepare() -> None:
    from cryptography.hazmat.primitives import serialization
    from tests import pki

    root = pki.make_ca("Smoke Test Root CA", path_length=1)
    inter = pki.make_ca("Smoke Test Qualified CA", parent=root, path_length=0)
    leaf = pki.make_signer_cert(inter, GIVEN, FAMILY, serial=f"PNOBG-{synthetic_egn()}")
    SMOKE.mkdir(exist_ok=True)
    (SMOKE / "anchors").mkdir(exist_ok=True)
    (SMOKE / "anchors" / "root.pem").write_bytes(root.cert.public_bytes(serialization.Encoding.PEM))
    der = lambda c: base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()  # noqa: E731
    (SMOKE / "signer.json").write_text(json.dumps({
        "key": base64.b64encode(leaf.key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode(),
        "cert": der(leaf.cert), "chain": [der(inter.cert)],
    }))
    (SMOKE / "signer.json").chmod(0o600)

    env_path = HERE / ".env"
    lines = [l for l in env_path.read_text().splitlines() if not l.startswith(("ANCHORS_DIR=", "EIDAS_REVOCATION="))]
    lines += ["ANCHORS_DIR=./.smoke/anchors", "EIDAS_REVOCATION=off"]
    env_path.write_text("\n".join(lines) + "\n")
    print("Synthetic CA written to .smoke/ and .env now trusts it (revocation off, for the test only).")
    print("Restart the verifier (the eID notary) so it picks that up:  docker compose up -d verifier")
    print("Before using the stack for real, remove those two lines from .env and the .smoke/ folder.")


def synthetic_egn() -> str:
    """A well-formed Bulgarian personal number for a made-up adult born 1985-06-15 (checksum included)."""
    prefix = "850615123"
    check = sum(w * int(d) for w, d in zip((2, 4, 8, 5, 10, 9, 7, 3, 6), prefix)) % 11
    return prefix + str(check if check < 10 else 0)


def synthetic_signer():
    from asn1crypto import x509 as asn1_x509
    from cryptography.hazmat.primitives import serialization

    data = json.loads((SMOKE / "signer.json").read_text())

    class Signer:
        hash_alg = "sha256"
        certificate = asn1_x509.Certificate.load(base64.b64decode(data["cert"]))
        chain = [asn1_x509.Certificate.load(base64.b64decode(c)) for c in data["chain"]]
        _key = serialization.load_der_private_key(base64.b64decode(data["key"]), None)

        def sign(self, payload: bytes) -> bytes:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            return self._key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    return Signer()


# --- the run ---------------------------------------------------------------------------------------------


async def follow(http: aiohttp.ClientSession, url: str, stop_at: str | None = None, limit: int = 12) -> tuple[str, aiohttp.ClientResponse | None]:
    """Follow redirects by hand (the sign-in secret lives in a URL fragment a client library would drop)."""
    for _ in range(limit):
        if stop_at and urlparse(url).path.startswith(stop_at):
            return url, None
        resp = await http.get(url.split("#")[0], allow_redirects=False)
        location = resp.headers.get("Location")
        if resp.status in (301, 302, 303, 307, 308) and location:
            url = urljoin(url, location)
            continue
        return url, resp
    raise RuntimeError("too many redirects")


async def wait_ready(http: aiohttp.ClientSession, url: str, seconds: int = 90) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            async with http.get(url, allow_redirects=False) as resp:
                if resp.status < 500:
                    return
        except aiohttp.ClientError:
            pass
        await asyncio.sleep(1.5)
    raise RuntimeError(f"{url} did not come up")


async def sign_in(env: dict[str, str], resolver, wallet, check: Check, share_claims: bool, label: str, choose=None) -> dict:
    """One complete OIDC sign-in through the relying party, approved by the wallet."""
    node, rp = env["NODE_URL"], env["RP_URL"]
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=resolver), cookie_jar=jar) as browser:
        login_url, _ = await follow(browser, rp + "/", stop_at="/oidc/login/")
        check.expect("/oidc/login/" in login_url and "#" in login_url, f"{label}: the application sends the browser to the Nodetide sign-in page")
        page_url, secret = login_url.split("#", 1)

        preview = await wallet("POST", "/api/signin/preview", {"login_url": page_url})
        asked = [c["claim_type"] for c in preview["claims_requested"]]
        check.expect({"email", "legal_name"} <= set(asked) or {"email"} <= set(asked), f"{label}: the wallet sees what the application asked for", ", ".join(asked))
        # one value per claim type: the holder's default unless a choice is made
        defaults = [c for c in preview["candidates"] if c["default"]]
        share = [c["attestation_id"] for c in (choose(preview["candidates"]) if choose else defaults)] if share_claims else []
        approval = await wallet("POST", "/api/signin/approve", {"token": preview["token"], "share": share})
        check.expect(approval.get("http_status") == 200, f"{label}: the wallet's approval is accepted", approval.get("message", ""))

        status = {}
        for _ in range(20):
            async with browser.get(page_url + "/status", headers={"X-Login-Secret": secret}) as resp:
                status = await resp.json()
            if status["status"] == "approved":
                break
            await asyncio.sleep(0.5)
        check.expect(status.get("status") == "approved", f"{label}: the sign-in page reports approval")

        final, resp = await follow(browser, status["redirect_to"])
        check.expect(resp is not None and resp.status == 200, f"{label}: the application accepts the id_token and serves the page")
        async with browser.get(rp + "/claims.json") as resp:
            claims = await resp.json()
    return claims


async def phone_check(http, env, wallet, identity, verifier_info, check: "Check") -> None:
    token = env.get("SMS_GATEWAY_TOKEN")
    if not token:
        print("  skip  no SMS_GATEWAY_TOKEN in .env")
        return
    number = "+359881234567"
    state = await wallet("GET", "/api/state")
    claim = next((c for c in state["claims"] if c["claim_type"] == "phone" and c["value"] == number), None)
    claim_id = claim["claim_id"] if claim else (await wallet("POST", "/api/claims/phone", {"number": number}))["claim_id"]
    sink = SMOKE / "sms.log"
    SMOKE.mkdir(exist_ok=True)
    sink.unlink(missing_ok=True)
    (SMOKE / "sms-ledger.json").unlink(missing_ok=True)  # a fresh gateway ledger for every run
    await wallet("POST", f"/api/claims/{claim_id}/verify-email")
    # the gateway script runs next to the modem; here it runs on this machine with the modem replaced by a file
    gateway = Path(__file__).resolve().parents[2] / "tools" / "sms-gateway" / "sms_gateway.py"
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(gateway), "--server", f"http://127.0.0.1:{env.get('VERIFIER_PORT', '4575')}", "--dry-run",
        "--dry-run-file", str(sink), "--once", "--state", str(SMOKE / "sms-ledger.json"),
        env={**os.environ, "SMS_GATEWAY_TOKEN": token}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await proc.communicate()
    check.expect(proc.returncode == 0 and sink.exists(), "the gateway fetched the queued SMS and 'sent' it", out.decode()[-200:] if proc.returncode else "")
    sent = [json.loads(line) for line in sink.read_text().splitlines()] if sink.exists() else []
    check.expect(len(sent) == 1 and sent[0]["to"] == number, "exactly one SMS, to the claimed number")
    code = re.search(r"code: ([0-9]{6})", sent[0]["text"]).group(1) if sent else ""
    attested = await wallet("POST", f"/api/claims/{claim_id}/confirm-email", {"code": code})
    check.expect(attested["attestation"]["method"] == "sms_code" and attested["attestation"]["issuer"] == verifier_info["issuer"],
                 "phone claim verified with the SMS code, signed by the verification service")


def mail_url(env: dict[str, str]) -> str:
    """Where the verifier's mail lands. The catch-all mailbox UI is bound to this machine's loopback."""
    return os.environ.get("SMOKE_MAIL_URL") or f"http://127.0.0.1:{env.get('MAIL_PORT', '4573')}"


async def mailbox_code(http: aiohttp.ClientSession, base: str, address: str, since: float, wait: float = 20) -> str:
    deadline = time.time() + wait
    while time.time() < deadline:
        async with http.get(f"{base}/api/v1/messages", params={"limit": 25}) as resp:
            listing = await resp.json(content_type=None)
        for message in listing.get("messages", []):
            if any(t.get("Address", "").lower() == address.lower() for t in message.get("To", [])):
                async with http.get(f"{base}/api/v1/message/{message['ID']}") as resp:
                    text = (await resp.json(content_type=None)).get("Text", "")
                match = re.search(r"Verification code: ([A-Z0-9]{8})", text)
                if match:
                    return match.group(1)
        await asyncio.sleep(1)
    raise RuntimeError(f"no verification email for {address} arrived at {base}")


async def run() -> int:
    env = load_env()
    check = Check()
    node, rp = env["NODE_URL"], env["RP_URL"]
    # the server-side test wallet is not public: smoke talks to it on the loopback port (start it with --profile hosted-wallet)
    wallet_url = f"http://127.0.0.1:{env.get('WALLET_PORT') or '4572'}"
    auth_header = "Basic " + base64.b64encode(f"wallet:{env['WALLET_PASSWORD']}".encode()).decode()
    resolver = PinLocal()
    eid = (SMOKE / "signer.json").exists()

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=resolver)) as http:
        print("services")
        await wait_ready(http, node + "/health")
        await wait_ready(http, wallet_url + "/healthz")
        async with http.get(rp + "/ping") as resp:
            check.expect(resp.status == 200, "relying party (oauth2-proxy) is up")
        async with http.get(node + "/.well-known/openid-configuration") as resp:
            discovery = await resp.json()
        check.expect(discovery["issuer"] == node, "OIDC discovery names the public issuer", discovery["issuer"])
        verifier_url = env["VERIFIER_URL"]
        await wait_ready(http, verifier_url + "/health")
        async with http.get(node + "/api/verify/issuer") as resp:
            check.expect(resp.status == 404, "the node itself verifies nothing")
        async with http.get(verifier_url + "/api/verify/issuer") as resp:
            verifier_info = await resp.json()
            check.expect(resp.status == 200, "the independent verification service is up", verifier_info.get("issuer", "")[:16])

        async def wallet(method: str, path: str, body: dict | None = None, raw: bytes | None = None) -> dict:
            async with http.request(method, wallet_url + path, json=body if raw is None else None, data=raw,
                                    headers={"Accept": "application/json", "Authorization": auth_header}) as resp:
                data = await resp.json(content_type=None)
                if resp.status >= 400:
                    raise RuntimeError(f"wallet {method} {path}: {resp.status} {data}")
                return data

        print("claims")
        state = await wallet("GET", "/api/state")
        identity = state["identity"]
        email_claim = next((c for c in state["claims"] if c["claim_type"] == "email" and c["value"] == EMAIL), None)
        if email_claim is None:
            email_claim = {"claim_id": (await wallet("POST", "/api/claims/email", {"address": EMAIL}))["claim_id"]}
        started_at = time.time()
        await wallet("POST", f"/api/claims/{email_claim['claim_id']}/verify-email")
        # the person reads the email and types the code: here the smoke test plays the person, from the catch-all mailbox
        code = await mailbox_code(http, mail_url(env), EMAIL, started_at)
        attested = await wallet("POST", f"/api/claims/{email_claim['claim_id']}/confirm-email", {"code": code})
        check.expect(attested["attestation"]["method"] == "email_code", "email claim verified with the code from the email")
        check.expect(attested["attestation"]["issuer"] == verifier_info["issuer"], "the attestation is signed by the verification service's own identity")
        check.expect(attested["attestation"]["issuer"] != identity, "and not by the holder")

        print("phone (SMS through the gateway script, dry run)")
        await phone_check(http, env, wallet, identity, verifier_info, check)

        if eid:
            print("eID (synthetic CA), attested by the notary")
            def claim_id_of(claim_type, make):
                found = next((c for c in state["claims"] if c["claim_type"] == claim_type), None)
                return found["claim_id"] if found else None

            name_id = claim_id_of("legal_name", None) or (await wallet("POST", "/api/claims/name", {"given": GIVEN, "family": FAMILY}))["claim_id"]
            age_id = claim_id_of("age_over_18", None) or (await wallet("POST", "/api/claims/age"))["claim_id"]
            born_id = claim_id_of("birthdate", None) or (await wallet("POST", "/api/claims/birthdate", {"date": "1985-06-15"}))["claim_id"]
            # the person lists legal name and "over 18" but NOT the birth date
            statement = (await wallet("POST", "/api/eid/statement", {"claims": [name_id, age_id]}))["statement"]
            from datetime import datetime, timezone
            from nodetide.eidas.cms import create_cades_detached
            from nodetide.eidas.notary_statement import parse_notary_statement
            parsed = parse_notary_statement(statement)
            check.expect(parsed.notary == verifier_info["issuer"], "the statement names the verification service as the notary")
            der = create_cades_detached(statement.encode(), synthetic_signer(), datetime.fromtimestamp(parsed.signed_on, tz=timezone.utc))
            uploaded = await wallet("POST", "/api/eid/signature", raw=der)
            types = sorted(a["claim_type"] for a in uploaded["attestations"])
            check.expect(types == ["age_over_18", "legal_name"], "the notary attested exactly the claims that were listed", str(types))
            leaked = [needle for needle in (synthetic_egn(), "PNOBG", "1985") if needle in json.dumps(uploaded)]
            check.expect(not leaked, "the attestations contain no personal number, no birth date and no certificate", str(leaked))
            check.expect(all(a["issuer"] == verifier_info["issuer"] and not a.get("proof") for a in uploaded["attestations"]),
                         "they are signed by the service identity, with no embedded proof")
            state = await wallet("GET", "/api/state")
            born = next(c for c in state["claims"] if c["claim_id"] == born_id)
            check.expect(not born["attestations"], "the birth date claim has no attestation: it was left out")

        print("explorer privacy")
        async with http.get(f"{node}/api/explorer/identities/{identity}") as resp:
            text = await resp.text()
        check.expect(resp.status == 200 and EMAIL not in text, "the explorer shows the wallet's claims but not the email address")

        print("sign-in through a standard OIDC client")
        shared = await sign_in(env, resolver, wallet, check, True, "sharing")
        check.expect(shared.get("sub") == identity, "id_token subject is the wallet's identity hash")
        check.expect(shared.get("email") == EMAIL and shared.get("email_verified") is True, "verified email released")
        if eid:
            check.expect(shared.get("name") == f"{GIVEN} {FAMILY}" and shared.get("name_verified") is True, "verified legal name released")
            frameworks = [v["verification"]["trust_framework"] for v in shared.get("verified_claims", [])]
            check.expect(frameworks == ["eidas"], "verified_claims names the eIDAS trust framework", str(frameworks))
            check.expect("birthdate" not in shared and "age_over_18" not in shared, "age and birth date are not released: this application did not ask")

        print("several verified emails: a default, and a choice on the approve page")
        second = "second@example.com"
        second_id = (await wallet("POST", "/api/claims/email", {"address": second}))["claim_id"]
        started_at = time.time()
        await wallet("POST", f"/api/claims/{second_id}/verify-email")
        await wallet("POST", f"/api/claims/{second_id}/confirm-email",
                     {"code": await mailbox_code(http, mail_url(env), second, started_at)})
        both = await sign_in(env, resolver, wallet, check, True, "default email")
        check.expect(both.get("email") == EMAIL, "the first email stays the default", str(both.get("email")))
        order = await wallet("POST", f"/api/claims/{second_id}/order", {"how": "default"})
        check.expect(order["order"][0] == second_id, "the second email is made the default (an event on the identity's chain)")
        switched = await sign_in(env, resolver, wallet, check, True, "new default")
        check.expect(switched.get("email") == second, "the new default is what the application receives", str(switched.get("email")))
        picked = await sign_in(env, resolver, wallet, check, True, "explicit choice",
                               choose=lambda cs: [c for c in cs if c["claim_type"] == "email" and not c["default"]])
        check.expect(picked.get("email") == EMAIL, "choosing the other email on the approve page releases that one", str(picked.get("email")))

        private = await sign_in(env, resolver, wallet, check, False, "not sharing")
        check.expect("email" not in private and "verified_claims" not in private, "nothing is released when the wallet shares nothing")
        check.expect(private.get("name_verified") is False, "only the self-asserted display name remains, labelled as such")

    print("\nPASSED" if not check.failed else f"\n{check.failed} check(s) FAILED")
    return 1 if check.failed else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["prepare", "run"])
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    else:
        raise SystemExit(asyncio.run(run()))


if __name__ == "__main__":
    main()
