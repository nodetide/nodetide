"""Test wallet: stands in for the Nodetide app that does not exist yet.

It holds one development identity (keys in plain JSON in its volume: never put anything real
here), makes claims, and gets them attested by the independent verification service: email and
phone with a one-time code, legal name / birth date / "over 18" by that service acting as an eID
notary on a statement you sign with your own eID card (the signature, which contains your
certificate, goes to the notary only and is not kept). It approves OIDC sign-ins while choosing
which claims to reveal. Everything is behind HTTP basic auth.

Every action is a JSON endpoint under /api (send `Accept: application/json`); the HTML forms
post to the same endpoints and are redirected back to the dashboard.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import socket
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse, urlunparse

import aiohttp
from aiohttp import web
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

from nodetide.core.auth import create_assertion
from nodetide.core.claims import Attestation, ClaimDocument, ClaimError
from nodetide.core.crypto import EncryptionPublicKey, KeyPair
from nodetide.core.identity import DeviceCapability, Identity, Sigchain
from nodetide.eidas.notary_statement import NOTARIZABLE, build_notary_statement

log = logging.getLogger("wallet")

NODE_URL = os.environ["NODE_URL"].rstrip("/")
WALLET_URL = os.environ.get("WALLET_URL", "").rstrip("/")
VERIFIER_URL = os.environ.get("VERIFIER_URL", "").rstrip("/")  # the independent email verification service
PASSWORD = os.environ["WALLET_PASSWORD"]
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
STATE_FILE = DATA_DIR / "wallet.json"
# WALLET_KEY_STORE=keychain: wallet.json is encrypted with a random key that lives in the macOS Keychain (keys, claim
# values and attestations never sit on disk in clear). Unset (the server's container): plain JSON, as before.
KEY_STORE = os.environ.get("WALLET_KEY_STORE", "")
KEYCHAIN_SERVICE = "nodetide-test-wallet"
STATE_MAGIC = b"NTW1"
# WALLET_LOCAL_APP=1 (the macOS menu-bar app): the browser is logged in by a one-time launch link that the app opens,
# so nobody types the HTTP password; the session cookie is HttpOnly and not sent on cross-site POSTs.
LOCAL_APP = os.environ.get("WALLET_LOCAL_APP") == "1"
LAUNCH_TTL = 60
# WALLET_START=pair: a wallet with no state yet starts as one more device of an identity held elsewhere (see "Pairing").
START = os.environ.get("WALLET_START", "")
PAIRING_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0 O 1 I L
PAIRING_LENGTH = 10  # about 49 bits: the node only ever sees its hash
PAIRING_PATHS = {"/", "/healthz", "/launch", "/api/pairing/restart", "/api/pairing/new-identity"}
launch_tokens: dict[str, float] = {}
sessions: set[str] = set()
STATEMENT_DAYS = 7
SIGNIN_TTL = 600
ASSURANCE_RANK = {"low": 0, "substantial": 1, "high": 2}
CODE_CLAIMS = ("email", "phone")  # verified by the verification service with a one-time code


class WalletError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# --- state ---------------------------------------------------------------------------------------


def state_box(create: bool) -> SecretBox:
    """The cipher for wallet.json, keyed by a 32-byte secret kept in the macOS Keychain (one per state file)."""
    if KEY_STORE != "keychain":
        raise SystemExit("WALLET_KEY_STORE must be 'keychain' (or unset for a plain state file)")
    import keyring  # only needed here

    account = str(STATE_FILE.resolve())
    stored = keyring.get_password(KEYCHAIN_SERVICE, account)
    if stored is None:
        if not create:
            raise SystemExit(f"wallet.json is encrypted but its key is not in the Keychain ({KEYCHAIN_SERVICE} / {account})")
        stored = secrets.token_hex(32)
        keyring.set_password(KEYCHAIN_SERVICE, account, stored)
    return SecretBox(bytes.fromhex(stored))


def load_state() -> tuple[dict[str, Any], bool]:
    """The saved state, and whether it still has to be rewritten encrypted (a plain file found in Keychain mode)."""
    if not STATE_FILE.exists():
        return {}, False
    raw = STATE_FILE.read_bytes()
    if raw.startswith(STATE_MAGIC):
        try:
            return json.loads(state_box(create=False).decrypt(raw[len(STATE_MAGIC):])), False
        except CryptoError:
            raise SystemExit("wallet.json cannot be decrypted with the Keychain key (wrong key or damaged file)") from None
    return json.loads(raw), KEY_STORE == "keychain"


class Wallet:
    def __init__(self) -> None:
        self.state, migrate = load_state()
        self.pending: dict[str, dict[str, Any]] = {}  # sign-in previews waiting for approval
        if migrate:
            self.save()

    def save(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        data = json.dumps(self.state, indent=2, ensure_ascii=False).encode()
        if KEY_STORE:
            data = STATE_MAGIC + state_box(create=True).encrypt(data)
        tmp = STATE_FILE.with_name(STATE_FILE.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, STATE_FILE)

    def ensure_identity(self) -> None:
        if self.state:
            return
        if START == "pair":
            label = (os.environ.get("WALLET_DEVICE_LABEL") or socket.gethostname() or "wallet")[:64]
            self.state = {"pairing": {"device": KeyPair.generate().to_dict(), "label": label}}
            self.save()
            return
        self.create_identity()

    def create_identity(self) -> None:
        identity = Identity.create(name="Test wallet")
        device, _ = identity.add_device(
            "test wallet", capabilities=[DeviceCapability.AUTHENTICATE, DeviceCapability.MANAGE_CLAIMS])
        assert identity.local_keypair is not None
        self.state = {"master": identity.local_keypair.to_dict(), "device": device.to_dict(),
                      "sigchain": identity.sigchain.to_list(), "claims": {}, "attestations": [], "statements": {}}
        self.save()

    @property
    def identity(self) -> Identity:
        master = self.state.get("master")  # absent on a device that was paired: it never holds the master key
        return Identity(sigchain=Sigchain.from_list(self.state["sigchain"]),
                        local_keypair=KeyPair.from_dict(master) if master else None)

    @property
    def signer(self) -> KeyPair | None:
        """Who signs claim events: the master key where we hold it, else this device (it has manage_claims)."""
        return None if self.state.get("master") else self.device

    @property
    def device(self) -> KeyPair:
        return KeyPair.from_dict(self.state["device"])

    def documents(self, claim_type: str | None = None) -> list[ClaimDocument]:
        docs = [ClaimDocument.from_dict(d) for d in self.state["claims"].values()]
        return [d for d in docs if claim_type in (None, d.claim_type)]

    def document(self, claim_id: str) -> ClaimDocument:
        if claim_id not in self.state["claims"]:
            raise WalletError("unknown claim", 404)
        return ClaimDocument.from_dict(self.state["claims"][claim_id])

    def add_claim(self, claim_type: str, value: Any) -> ClaimDocument:
        identity = self.identity
        try:
            document = ClaimDocument.create(identity.identity_hash or "", claim_type, value)
        except ClaimError as e:
            raise WalletError(str(e)) from None
        identity.add_claim(document.claim_id, claim_type, document.commitment, signer=self.signer)
        self.state["claims"][document.claim_id] = document.to_dict()
        self.state["sigchain"] = identity.sigchain.to_list()
        self.save()
        return document

    def add_attestation(self, attestation: dict[str, Any], verdict: str) -> None:
        attestation = {**attestation, "_node_verdict": verdict}
        self.state["attestations"] = [a for a in self.state["attestations"]
                                      if not (a["claim_id"] == attestation["claim_id"] and a["method"] == attestation["method"])]
        self.state["attestations"].append(attestation)
        self.save()


wallet = Wallet()


# --- talking to the node ---------------------------------------------------------------------------


async def node(method: str, path: str, **kw: Any) -> tuple[int, Any]:
    return await call(NODE_URL, method, path, **kw)


async def verifier(method: str, path: str, **kw: Any) -> tuple[int, Any]:
    if not VERIFIER_URL:
        raise WalletError("no verification service is configured (VERIFIER_URL)", 501)
    return await call(VERIFIER_URL, method, path, **kw)


async def call(base: str, method: str, path: str, **kw: Any) -> tuple[int, Any]:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as http:
        async with http.request(method, base + path, **kw) as resp:
            try:
                return resp.status, await resp.json(content_type=None)
            except Exception:
                return resp.status, {"error": "non_json", "message": (await resp.text())[:200]}


async def publish() -> int:
    """Send the identity's events the node does not have yet."""
    identity = wallet.identity
    events = identity.sigchain.to_list()
    status, body = await node("GET", f"/api/identities/{identity.identity_hash}/sigchain")
    known = body.get("length", 0) if status == 200 else 0
    for index in range(known, len(events)):
        path = "/api/identities" if index == 0 else f"/api/identities/{identity.identity_hash}/events"
        status, body = await node("POST", path, json={"event": events[index]})
        if status not in (200, 201):
            raise WalletError(f"the node refused event {index}: {body}", 502)
    return len(events) - known


async def publish_forever(app: web.Application) -> None:
    while True:
        try:
            await publish()
            return
        except (WalletError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            log.warning("waiting for the node: %s", e)
            await asyncio.sleep(3)


async def start_email_verification(claim_id: str) -> dict[str, Any]:
    """Ask the verification service to email a code. The person reads the mail and types the code (confirm_email)."""
    document = wallet.document(claim_id)
    if document.claim_type not in CODE_CLAIMS:
        raise WalletError("only email and phone claims are verified with a code")
    identity = wallet.identity
    status, request = await verifier("POST", "/api/auth/challenge", json={})
    if status != 201:
        raise WalletError(f"the verification service refused a challenge: {request}", 502)
    assertion = create_assertion(request, identity.identity_hash or "", wallet.device, identity.sigchain.head_hash or "",
                                 claims={"purpose": "claim_verification", "claim_id": claim_id})
    status, begun = await verifier("POST", f"/api/verify/{document.claim_type}/start", json={
        "document": document.to_dict(), "assertion": assertion, "sigchain": identity.sigchain.to_list()})
    if status != 202:
        raise WalletError(f"verification not started: {begun.get('message', begun)}", 502)
    wallet.state.setdefault("verifications", {})[claim_id] = {
        "verification_id": begun["verification_id"], "expires_at": begun["expires_at"], "kind": document.claim_type}
    wallet.save()
    return {"expires_at": begun["expires_at"], "message": begun.get("message", "")}


async def confirm_email(claim_id: str, code: str) -> dict[str, Any]:
    pending = wallet.state.get("verifications", {}).get(claim_id)
    if pending is None:
        raise WalletError("start the verification first")
    status, confirmed = await verifier("POST", f"/api/verify/{pending.get('kind', 'email')}/confirm",
                                       json={"verification_id": pending["verification_id"], "code": str(code).strip()})
    if status != 201:
        raise WalletError(confirmed.get("message", f"code not accepted: {confirmed}"), 502 if status >= 500 else 400)
    # keep the issuer's chain with the attestation, so it can be shown anywhere without a lookup
    status, info = await verifier("GET", "/api/verify/issuer")
    attestation = confirmed["attestation"]
    if status == 200 and info.get("issuer") == attestation["issuer"]:
        wallet.state.setdefault("issuer_chains", {})[attestation["issuer"]] = info["sigchain"]
        who = info.get("name") or attestation["issuer"][:12]
    else:
        who = attestation["issuer"][:12]
    wallet.state["verifications"].pop(claim_id, None)
    wallet.add_attestation(attestation, f"issued by {who}")
    return attestation


# --- statements and signatures ---------------------------------------------------------------------------


async def notary_info() -> dict[str, Any]:
    """Who the eID notary is (the verification service's identity) and what it can attest."""
    status, info = await verifier("GET", "/api/verify/issuer")
    method = next((m for m in info.get("methods", []) if m.get("method") == "eidas_notary"), None) if status == 200 else None
    if method is None:
        raise WalletError("the verification service does not attest eID signatures", 501)
    return {"issuer": info["issuer"], "name": info.get("name") or info["issuer"][:12], "sigchain": info["sigchain"],
            "claim_types": method["claim_types"]}


async def new_notary_statement(claim_ids: list[str]) -> str:
    """The statement to sign with the card: it names the notary and lists exactly the claims to attest."""
    info = await notary_info()
    identity, now = wallet.identity, int(time.time())
    claims = []
    for claim_id in claim_ids:
        record = identity.sigchain.get_claim(claim_id)
        if record is None or record.claim_type not in info["claim_types"]:
            raise WalletError("only legal name, birth date and over-18 claims can be attested from an eID signature")
        claims.append((record.claim_id, record.claim_type, record.commitment))
    if not claims:
        raise WalletError("tick at least one claim")
    try:
        text = build_notary_statement(identity.identity_hash or "", info["issuer"], identity.sigchain.head_hash or "",
                                      now, now + STATEMENT_DAYS * 86400, claims)
    except ValueError as e:
        raise WalletError(str(e)) from None
    wallet.state["notary_statement"] = {"text": text, "claim_ids": claim_ids}
    wallet.save()
    return text


async def submit_signature(der: bytes) -> list[dict[str, Any]]:
    """Send the card's signature (it embeds the certificate, so the ID number) to the notary and nowhere else.

    The signature is not stored here; what comes back are attestations without it.
    """
    pending = wallet.state.get("notary_statement")
    if not pending:
        raise WalletError("create a statement first")
    info = await notary_info()
    identity, text = wallet.identity, pending["text"]
    status, request = await verifier("POST", "/api/auth/challenge", json={})
    if status != 201:
        raise WalletError(f"the notary refused a challenge: {request}", 502)
    assertion = create_assertion(request, identity.identity_hash or "", wallet.device, identity.sigchain.head_hash or "",
                                 claims={"purpose": "eid_attestation", "statement_sha256": hashlib.sha256(text.encode()).hexdigest()})
    status, body = await verifier("POST", "/api/verify/eid/attest", json={
        "statement": text, "signature": base64.b64encode(der).decode("ascii"),
        "documents": [wallet.document(c).to_dict() for c in pending["claim_ids"]],
        "assertion": assertion, "sigchain": identity.sigchain.to_list()})
    if status != 201:
        raise WalletError(f"the notary said: {body.get('message', body)}", 400 if status < 500 else 502)
    wallet.state.setdefault("issuer_chains", {})[info["issuer"]] = info["sigchain"]
    for attestation in body["attestations"]:
        wallet.add_attestation(attestation, f"attested by {info['name']} (eID notary)")
    wallet.state.pop("notary_statement", None)
    wallet.save()
    return body["attestations"]


# --- sign-in -------------------------------------------------------------------------------------------------


def challenge_url_from(login: str) -> str:
    login = login.strip()
    if login.startswith("nodetide://"):
        values = parse_qs(urlparse(login).query).get("challenge_url")
        if not values:
            raise WalletError("that deep link has no challenge_url")
        return values[0]
    url = urlparse(login)
    if url.scheme not in ("http", "https") or not url.netloc:
        raise WalletError("paste the sign-in address shown by the application")
    path = url.path.rstrip("/")
    if not path.endswith("/challenge"):
        path += "/challenge"
    return urlunparse(url._replace(path=path, query="", fragment=""))


async def signin_preview(login: str) -> dict[str, Any]:
    url = challenge_url_from(login)
    if urlparse(url).netloc != urlparse(NODE_URL).netloc:
        raise WalletError("this wallet only signs in to its own node")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as http:
        async with http.get(url) as resp:
            challenge = await resp.json(content_type=None)
            if resp.status != 200:
                raise WalletError(f"cannot fetch the challenge: {challenge}", 502)
    asked_types = [c["claim_type"] for c in challenge["display"].get("claims_requested", [])]
    now = int(time.time())
    docs = {d.claim_id: d for d in wallet.documents()}
    chain = wallet.identity.sigchain
    candidates: list[dict[str, Any]] = []
    for claim_type in dict.fromkeys(asked_types):
        # one candidate per claim (its best attestation), in the order the holder prefers: the first is the default
        for claim_id in chain.claim_order(claim_type):
            usable = [a for a in wallet.state["attestations"]
                      if a["claim_id"] == claim_id and a["expires_at"] > now and claim_id in docs]
            if not usable:
                continue
            best = max(usable, key=lambda a: (ASSURANCE_RANK[a["assurance"]], a["expires_at"]))
            clean = {k: v for k, v in best.items() if not k.startswith("_")}
            candidates.append({
                "attestation_id": Attestation.from_dict(clean).id, "claim_id": claim_id, "claim_type": claim_type,
                "method": best["method"], "assurance": best["assurance"], "expires_at": best["expires_at"],
                "value": docs[claim_id].value,
                "default": not any(c["claim_type"] == claim_type for c in candidates),
            })
    token = secrets.token_urlsafe(16)
    wallet.pending = {t: p for t, p in wallet.pending.items() if p["expires"] > now}
    wallet.pending[token] = {"challenge": challenge, "candidates": candidates, "expires": now + SIGNIN_TTL}
    return {"token": token, "client": challenge["display"]["client_name"], "issuer": challenge["display"]["issuer"],
            "claims_requested": challenge["display"].get("claims_requested", []), "candidates": candidates}


async def signin_approve(token: str, share: list[str]) -> dict[str, Any]:
    pending = wallet.pending.pop(token, None)
    if pending is None or pending["expires"] < time.time():
        raise WalletError("that sign-in preview expired; start again", 410)
    identity, challenge = wallet.identity, pending["challenge"]
    docs = {d.claim_id: d for d in wallet.documents()}
    presentations = []
    for att in wallet.state["attestations"]:
        clean = {k: v for k, v in att.items() if not k.startswith("_")}
        if Attestation.from_dict(clean).id in share and att["claim_id"] in docs:
            item = {"document": docs[att["claim_id"]].to_dict(), "attestation": clean}
            chain = wallet.state.get("issuer_chains", {}).get(att["issuer"])
            if chain:
                item["issuer_sigchain"] = chain
            presentations.append(item)
    types = [p["attestation"]["claim_type"] for p in presentations]
    if len(types) != len(set(types)):
        raise WalletError("choose one value per claim type (for example one email), not several")
    assertion = create_assertion(challenge["request"], identity.identity_hash or "", wallet.device,
                                 identity.sigchain.head_hash or "")
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as http:
        async with http.post(challenge["respond_url"], json={
                "assertion": assertion, "sigchain": identity.sigchain.to_list(), "presentations": presentations}) as resp:
            body = await resp.json(content_type=None)
            return {"http_status": resp.status, **body}


# --- web ---------------------------------------------------------------------------------------------------------


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def wants_json(request: web.Request) -> bool:
    return "application/json" in request.headers.get("Accept", "") or request.path.startswith("/api/state")


async def params(request: web.Request) -> dict[str, Any]:
    if request.content_type == "application/json":
        data = await request.json()
        return data if isinstance(data, dict) else {}
    if request.content_type in ("application/x-www-form-urlencoded", "multipart/form-data"):
        form = await request.post()
        return {k: (v if not isinstance(v, web.FileField) else v) for k, v in form.items()} \
            | {"_multi": {k: form.getall(k) for k in form}}
    return {}


def done(request: web.Request, data: dict[str, Any], message: str) -> web.Response:
    if wants_json(request):
        return web.json_response(data)
    raise web.HTTPSeeOther("/?msg=" + quote(message))


@web.middleware
async def errors(request: web.Request, handler):
    try:
        return await handler(request)
    except WalletError as e:
        if wants_json(request):
            return web.json_response({"error": str(e)}, status=e.status)
        raise web.HTTPSeeOther("/?err=" + quote(str(e)[:300])) from None


def launch_path() -> str:
    """A one-time link (valid for a minute) that logs a browser in."""
    for token, expires in list(launch_tokens.items()):
        if expires < time.time():
            del launch_tokens[token]
    token = secrets.token_urlsafe(24)
    launch_tokens[token] = time.time() + LAUNCH_TTL
    return "/launch?token=" + token


async def launch(request: web.Request) -> web.Response:
    expires = launch_tokens.pop(request.query.get("token", ""), 0)
    if expires < time.time():
        return web.Response(status=403, text="This link was used or has expired: open the wallet from the menu-bar icon again.")
    session = secrets.token_urlsafe(24)
    sessions.add(session)
    response = web.Response(status=303, headers={"Location": "/"})
    response.set_cookie("wallet_session", session, httponly=True, samesite="Lax", max_age=30 * 24 * 3600)
    return response


@web.middleware
async def basic_auth(request: web.Request, handler):
    if request.path == "/healthz" or (LOCAL_APP and request.path == "/launch"):
        return await handler(request)
    if LOCAL_APP and request.cookies.get("wallet_session") in sessions:
        return await handler(request)
    header = request.headers.get("Authorization", "")
    ok = False
    if header.lower().startswith("basic "):
        import base64
        try:
            _, _, supplied = base64.b64decode(header[6:]).decode().partition(":")
            ok = hmac.compare_digest(supplied.encode(), PASSWORD.encode())
        except Exception:
            ok = False
    if not ok:
        if LOCAL_APP:
            return web.Response(status=401, text="Open the wallet from the menu-bar icon.")
        return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="Nodetide test wallet"'}, text="login required")
    return await handler(request)


@web.middleware
async def pairing_gate(request: web.Request, handler):
    if "pairing" in wallet.state and request.path not in PAIRING_PATHS:
        raise WalletError("this wallet is waiting to be paired with your identity", 409)
    return await handler(request)


def state_view() -> dict[str, Any]:
    identity, now = wallet.identity, int(time.time())
    docs = {d.claim_id: d for d in wallet.documents()}
    claims = []
    orders = {t: identity.sigchain.claim_order(t) for t in {r.claim_type for r in identity.sigchain.get_claims()}}
    for record in identity.sigchain.get_claims():
        doc = docs.get(record.claim_id)
        atts = [{"attestation_id": Attestation.from_dict({k: v for k, v in a.items() if not k.startswith("_")}).id,
                 "method": a["method"], "assurance": a["assurance"], "expires_at": a["expires_at"],
                 "expired": a["expires_at"] <= now, "node_verdict": a.get("_node_verdict", "")}
                for a in wallet.state["attestations"] if a["claim_id"] == record.claim_id]
        order = orders.get(record.claim_type, [])
        rank = order.index(record.claim_id) + 1 if record.claim_id in order else None
        claims.append({"claim_id": record.claim_id, "claim_type": record.claim_type, "status": record.status(now),
                       "rank": rank, "default": rank == 1 and len(order) > 1,
                       "value": doc.value if doc else None, "attestations": atts,
                       })
    return {"identity": identity.identity_hash, "claims": claims}


async def api_state(request: web.Request) -> web.Response:
    return web.json_response(state_view())


async def api_claim_email(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("email", str(data.get("address", "")))
    await publish()
    return done(request, {"claim_id": document.claim_id}, "email claim created")


async def reorder(claim_id: str, how: str) -> str:
    """Make a claim the default of its type, or move it up or down; recorded on the identity's chain."""
    identity = wallet.identity
    record = identity.sigchain.get_claim(claim_id)
    if record is None or record.status() != "active":
        raise WalletError("unknown or inactive claim", 404)
    order = identity.sigchain.claim_order(record.claim_type)
    index = order.index(claim_id)
    if how == "default":
        order.insert(0, order.pop(index))
    elif how == "up" and index > 0:
        order[index - 1], order[index] = order[index], order[index - 1]
    elif how == "down" and index < len(order) - 1:
        order[index + 1], order[index] = order[index], order[index + 1]
    elif how not in ("default", "up", "down"):
        raise WalletError("how must be default, up or down")
    identity.set_claim_order(record.claim_type, order, signer=wallet.signer)
    wallet.state["sigchain"] = identity.sigchain.to_list()
    wallet.save()
    await publish()
    return record.claim_type


async def api_claim_order(request: web.Request) -> web.Response:
    data = await params(request)
    claim_type = await reorder(request.match_info["id"], str(data.get("how", "default")))
    return done(request, {"claim_type": claim_type, "order": wallet.identity.sigchain.claim_order(claim_type)},
                f"Order of your {claim_type} claims updated.")


async def api_claim_phone(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("phone", str(data.get("number", "")).replace(" ", ""))
    await publish()
    return done(request, {"claim_id": document.claim_id}, "phone claim created")


async def api_claim_name(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("legal_name", {"given_name": str(data.get("given", "")), "family_name": str(data.get("family", ""))})
    await publish()
    return done(request, {"claim_id": document.claim_id}, "legal name claim created")


async def api_verify_email(request: web.Request) -> web.Response:
    """Step 1: the verification service emails a code."""
    started = await start_email_verification(request.match_info["id"])
    return done(request, started, "A code was sent. Type it below to finish.")


async def api_confirm_email(request: web.Request) -> web.Response:
    """Step 2: the person types the code from the email."""
    data = await params(request)
    attestation = await confirm_email(request.match_info["id"], str(data.get("code", "")))
    return done(request, {"attestation": attestation}, "Verified.")


async def api_eid_statement(request: web.Request) -> web.Response:
    if request.method == "POST":
        data = await params(request)
        claim_ids = data.get("claims") if isinstance(data.get("claims"), list) else data.get("_multi", {}).get("claim", [])
        text = await new_notary_statement([str(c) for c in claim_ids])
        return done(request, {"statement": text}, "Statement created: download it and sign it with your card within 10 minutes.")
    pending = wallet.state.get("notary_statement")
    if not pending:
        raise WalletError("no statement yet", 404)
    return web.Response(body=pending["text"].encode("utf-8"), content_type="text/plain",
                        headers={"Content-Disposition": 'attachment; filename="notary-statement.txt"'})


async def api_eid_signature(request: web.Request) -> web.Response:
    if request.content_type == "multipart/form-data":
        reader = await request.multipart()
        der = b""
        async for part in reader:
            if part.name == "signature":
                der = await part.read(decode=False)
    else:
        der = await request.read()
    if not der:
        raise WalletError("no signature received")
    attestations = await submit_signature(der)
    types = ", ".join(sorted(a["claim_type"] for a in attestations))
    return done(request, {"attestations": attestations}, f"The notary attested: {types}. Your certificate was not kept.")


async def api_claim_birthdate(request: web.Request) -> web.Response:
    data = await params(request)
    document = wallet.add_claim("birthdate", str(data.get("date", "")))
    await publish()
    return done(request, {"claim_id": document.claim_id}, "birth date claim created")


async def api_claim_age(request: web.Request) -> web.Response:
    document = wallet.add_claim("age_over_18", True)
    await publish()
    return done(request, {"claim_id": document.claim_id}, "over-18 claim created")


async def api_signin_preview(request: web.Request) -> web.Response:
    data = await params(request)
    preview = await signin_preview(str(data.get("login_url", "")))
    if wants_json(request):
        return web.json_response(preview)
    return web.Response(text=signin_page(preview), content_type="text/html")


async def api_signin_approve(request: web.Request) -> web.Response:
    data = await params(request)
    share = data.get("share", [])
    if isinstance(share, str):
        share = [share]
    if "_multi" in data:
        multi = data["_multi"]
        share = list(multi.get("share", [])) + [v for k, vs in multi.items() if k.startswith("share_") for v in vs if v]
    result = await signin_approve(str(data.get("token", "")), [str(s) for s in share])
    if wants_json(request):
        return web.json_response(result)
    released = ", ".join(r["claim_type"] for r in (result.get("claims") or {}).get("released", [])) or "nothing"
    raise web.HTTPSeeOther("/?msg=" + quote(f"{result.get('message', '')} Released: {released}."))


# --- pairing: more devices for one identity -----------------------------------------------------------------------
#
# The identity is its sigchain on the node; the device holding the master key can authorize more devices on it. A new
# device makes its own keys and opens a "slot" on the node, named by the hash of a code it shows; the owner types the
# code into the wallet that holds the master key, which authorizes the new device (an add_device event) and leaves the
# claim values and attestations, sealed to the new device's key, in the slot. The node relays public keys and one
# sealed message; it can read neither the code nor the answer.


def pairing_slot(code: str) -> str:
    return hashlib.sha256(b"nodetide-pairing:" + code.encode()).hexdigest()


def normalize_code(text: Any) -> str:
    code = "".join(ch for ch in str(text).upper() if ch.isalnum())
    if len(code) != PAIRING_LENGTH or any(ch not in PAIRING_ALPHABET for ch in code):
        raise WalletError("that is not a pairing code (10 letters and digits, as shown on the new device)")
    return code


def show_code(code: str) -> str:
    return f"{code[:5]}-{code[5:]}"


def fingerprint(pubkey_hex: str) -> str:
    digest = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:12]
    return "-".join(digest[i:i + 4] for i in range(0, 12, 4))


async def open_pairing() -> None:
    """New device: publish a fresh code (also after the old one expired)."""
    pairing = wallet.state["pairing"]
    device = KeyPair.from_dict(pairing["device"])
    code = "".join(secrets.choice(PAIRING_ALPHABET) for _ in range(PAIRING_LENGTH))
    status, body = await node("POST", "/api/pairing", json={"slot": pairing_slot(code), "request": {
        "device_pubkey": device.verify_key.to_hex(),
        "device_encryption_pubkey": device.public_encryption_key.to_hex(), "label": pairing["label"]}})
    if status != 201:
        raise WalletError(f"the node did not open a pairing: {body}", 502)
    pairing["code"], pairing["expires_at"] = code, body["expires_at"]
    wallet.save()


async def check_pairing() -> bool:
    """New device: take the answer if it is there. True once this wallet has become a device of the identity."""
    pairing = wallet.state["pairing"]
    if not pairing.get("code") or pairing["expires_at"] <= time.time():
        await open_pairing()
        return False
    status, body = await node("GET", f"/api/pairing/{pairing_slot(pairing['code'])}")
    if status == 404:
        await open_pairing()
        return False
    if status != 200:
        raise WalletError(f"the node refused the pairing check: {body}", 502)
    if not body.get("response"):
        return False
    import_pairing(body["response"])
    try:
        await node("DELETE", f"/api/pairing/{pairing_slot(pairing['code'])}")
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass  # it expires by itself
    return True


def import_pairing(response: dict[str, Any]) -> None:
    """New device: open the sealed answer, check it against the identity's chain, and become a device of it."""
    pairing = wallet.state["pairing"]
    device = KeyPair.from_dict(pairing["device"])
    try:
        sender = EncryptionPublicKey.from_hex(response["from_encryption_pubkey"])
        payload = json.loads(device.encryption_key.decrypt(base64.b64decode(response["sealed"]), sender))
        chain = Sigchain.from_list(payload["sigchain"])
        documents = {cid: ClaimDocument.from_dict(d) for cid, d in payload["claims"].items()}
        attestations = list(payload["attestations"])
    except (ValueError, KeyError, TypeError, CryptoError, ClaimError) as e:
        raise WalletError(f"the answer could not be opened: {e}", 502) from None
    ok, why = chain.verify()
    if not ok:
        raise WalletError(f"the identity's chain does not verify: {why}", 502)
    devices = chain.get_active_devices()
    mine = next((d for d in devices if d.pubkey == device.verify_key.to_hex()), None)
    if (mine is None or mine.encryption_pubkey != device.public_encryption_key.to_hex()
            or DeviceCapability.MANAGE_CLAIMS.value not in mine.capabilities):
        raise WalletError("the identity has not authorized this device", 502)
    if not any(d.encryption_pubkey == response["from_encryption_pubkey"] for d in devices):
        raise WalletError("the answer did not come from a device of this identity", 502)
    for claim_id, document in documents.items():
        if claim_id != document.claim_id or not document.matches(chain.get_claim(claim_id)):
            raise WalletError("a claim in the answer does not match the identity's chain", 502)
    wallet.state = {"device": pairing["device"], "sigchain": chain.to_list(),
                    "claims": {cid: d.to_dict() for cid, d in documents.items()}, "attestations": attestations,
                    "statements": {}}
    wallet.save()


async def pairing_lookup(code_text: Any) -> tuple[str, dict[str, Any]]:
    """Wallet holding the master key: find the device that is waiting under this code."""
    if not wallet.state.get("master"):
        raise WalletError("this wallet does not hold the master key; add devices from the wallet that does", 403)
    code = normalize_code(code_text)
    status, body = await node("GET", f"/api/pairing/{pairing_slot(code)}")
    if status == 404:
        raise WalletError("no device is waiting under that code (it may have expired: ask the new device for a new one)", 404)
    if status != 200:
        raise WalletError(f"the node refused the lookup: {body}", 502)
    if body.get("response"):
        raise WalletError("that device has already been answered", 409)
    return code, body["request"]


async def pairing_approve(code_text: Any) -> str:
    code, request = await pairing_lookup(code_text)
    identity = wallet.identity
    identity.authorize_device(request["device_pubkey"], request["device_encryption_pubkey"], request["label"],
                              capabilities=[DeviceCapability.AUTHENTICATE, DeviceCapability.MANAGE_CLAIMS])
    wallet.state["sigchain"] = identity.sigchain.to_list()
    wallet.save()
    await publish()
    sealed = EncryptionPublicKey.from_hex(request["device_encryption_pubkey"]).encrypt(
        json.dumps({"sigchain": wallet.state["sigchain"], "claims": wallet.state["claims"],
                    "attestations": wallet.state["attestations"]}).encode(), wallet.device.encryption_key)
    status, body = await node("PUT", f"/api/pairing/{pairing_slot(code)}/response", json={"response": {
        "from_encryption_pubkey": wallet.device.public_encryption_key.to_hex(),
        "sealed": base64.b64encode(sealed).decode()}})
    if status != 201:
        raise WalletError(f"the node did not take the answer: {body}", 502)
    return request["label"]


async def api_pairing_preview(request: web.Request) -> web.Response:
    data = await params(request)
    code, device = await pairing_lookup(data.get("code", ""))
    if wants_json(request):
        return web.json_response({"label": device["label"], "fingerprint": fingerprint(device["device_pubkey"])})
    return web.Response(content_type="text/html", text=layout(f"""<h2>Add this device?</h2>
<p><b>{esc(device['label'])}</b>, key fingerprint <code>{fingerprint(device['device_pubkey'])}</code></p>
<p class="muted">The same fingerprint is shown on the new device. It will be able to add claims, sign you in and see
your claim values. Only continue if you started this pairing yourself.</p>
<form method="post" action="/api/devices/approve"><input type="hidden" name="code" value="{esc(show_code(code))}">
<button>Add the device</button> <a href="/">Cancel</a></form>"""))


async def api_pairing_approve(request: web.Request) -> web.Response:
    data = await params(request)
    label = await pairing_approve(data.get("code", ""))
    return done(request, {"label": label}, f"{label} is now a device of your identity. It will pick up your claims in a moment.")


async def api_pairing_restart(request: web.Request) -> web.Response:
    if "pairing" not in wallet.state:
        raise WalletError("this wallet is not waiting to be paired", 409)
    await open_pairing()
    raise web.HTTPSeeOther("/")


async def api_pairing_new_identity(request: web.Request) -> web.Response:
    if "pairing" not in wallet.state:
        raise WalletError("this wallet is not waiting to be paired", 409)
    wallet.create_identity()
    raise web.HTTPSeeOther("/?msg=" + quote("A new identity was created for this wallet."))


async def pairing_dashboard(request: web.Request) -> web.Response:
    """What a wallet waiting to be paired shows (it refreshes itself until the answer arrives)."""
    problem = ""
    try:
        if await check_pairing():
            raise web.HTTPSeeOther("/?msg=" + quote("Paired: this wallet is now a device of your identity."))
    except (WalletError, aiohttp.ClientError, asyncio.TimeoutError) as e:
        problem = f"Waiting for the node: {e}"
    pairing = wallet.state["pairing"]
    device = KeyPair.from_dict(pairing["device"])
    code = pairing.get("code")
    shown = (f'<p style="font-size:2rem"><code>{esc(show_code(code))}</code></p>' if code else "<p>Getting a code...</p>")
    return web.Response(content_type="text/html", text=layout(f"""<meta http-equiv="refresh" content="3">
<h2>Pair this wallet with your identity</h2>
<p>In the wallet that already holds your identity, open <b>Devices</b> and choose <b>Add a device</b>, then enter:</p>
{shown}
<p class="muted">This device: <b>{esc(pairing['label'])}</b>, key fingerprint <code>{fingerprint(device.verify_key.to_hex())}</code>
(the other wallet shows it before you confirm). The code works for about ten minutes; this page waits for the answer.</p>
{f'<p class="err">{esc(problem)}</p>' if problem else ''}
<form method="post" action="/api/pairing/restart" style="display:inline"><button>New code</button></form>
<form method="post" action="/api/pairing/new-identity" style="display:inline"
 onsubmit="return confirm('Start a separate, new identity instead of pairing?')"><button>Start a new identity instead</button></form>""", request))


# --- pages ---------------------------------------------------------------------------------------------------------

CSS = """body{font:16px/1.5 system-ui,sans-serif;max-width:52rem;margin:1.5rem auto;padding:0 1rem}
code{word-break:break-all;background:#eee;padding:0 .25rem;border-radius:.2rem}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}
form{margin:.4rem 0}input[type=text],input[type=url],input[type=email]{width:min(28rem,100%)}
.msg{background:#e6f6ec;padding:.5rem 1rem;border-radius:.3rem}.err{background:#fde8e8;padding:.5rem 1rem;border-radius:.3rem}
.muted{color:#666}"""


def layout(body: str, request: web.Request | None = None) -> str:
    note = ""
    if request is not None:
        if request.query.get("msg"):
            note += f'<p class="msg">{esc(request.query["msg"])}</p>'
        if request.query.get("err"):
            note += f'<p class="err">{esc(request.query["err"])}</p>'
    return f"""<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nodetide test wallet</title><style>{CSS}</style><h1>Nodetide test wallet</h1>{note}{body}"""


def signin_page(preview: dict[str, Any]) -> str:
    asked = ", ".join(c["claim_type"] for c in preview["claims_requested"]) or "nothing beyond your identity"
    groups: dict[str, list[dict[str, Any]]] = {}
    for c in preview["candidates"]:
        groups.setdefault(c["claim_type"], []).append(c)
    blocks = []
    for claim_type, options in groups.items():
        radios = "".join(
            f'<label><input type="radio" name="share_{esc(claim_type)}" value="{esc(c["attestation_id"])}"'
            f'{" checked" if c["default"] else ""}> {esc(json.dumps(c["value"], ensure_ascii=False))} '
            f'<span class="muted">({esc(c["method"])} / {esc(c["assurance"])}{", your default" if c["default"] and len(options) > 1 else ""})'
            f'</span></label><br>' for c in options)
        radios += (f'<label><input type="radio" name="share_{esc(claim_type)}" value=""> '
                   f'<span class="muted">share no {esc(claim_type)}</span></label>')
        blocks.append(f"<p><b>{esc(claim_type)}</b><br>{radios}</p>")
    chosen = "".join(blocks) if blocks else '<p class="muted">You hold no attestation that fits; you will sign in with your identity only.</p>'
    return layout(f"""<h2>Approve sign-in?</h2>
<p><b>{esc(preview['client'])}</b> (via <code>{esc(preview['issuer'])}</code>) asks for: {esc(asked)}.</p>
<p class="muted">Pick what to reveal, one value per kind. Your default is preselected; change defaults on the <a href="/">dashboard</a>.</p>
<form method="post" action="/api/signin/approve"><input type="hidden" name="token" value="{esc(preview['token'])}">
{chosen}<p><button>Approve</button> <a href="/">Cancel</a></p></form>""")


async def signin_link(request: web.Request) -> web.Response:
    """GET /signin?link=...  the "open in wallet" link on the node's sign-in page. Only previews: approving is a POST."""
    link = request.query.get("link", "")
    return web.Response(text=signin_page(await signin_preview(link)), content_type="text/html")


def eid_form(view: dict[str, Any]) -> str:
    eligible = [c for c in view["claims"] if c["claim_type"] in NOTARIZABLE]
    if not eligible:
        return ('<h2>Prove claims with your eID card</h2><p class="muted">Add a legal name, birth date or over-18 claim '
                'first; then you can have them attested from your eID signature.</p>')
    boxes = "".join(
        f'<label><input type="checkbox" name="claim" value="{esc(c["claim_id"])}"> {esc(c["claim_type"])}: '
        f'{esc(json.dumps(c["value"], ensure_ascii=False))}</label><br>' for c in eligible)
    pending = wallet.state.get("notary_statement")
    step2 = ""
    if pending:
        step2 = ('<p><b>Statement ready.</b> <a href="/api/eid/statement">download it</a>, sign it with your card '
                 '(<code>nodetide eid sign-file notary-statement.txt</code>, within 10 minutes), then upload the .p7s. '
                 'It goes to the notary only and is not kept here.</p>'
                 '<form method="post" action="/api/eid/signature" enctype="multipart/form-data">'
                 '<input type="file" name="signature" required> <button>Send to the notary</button></form>'
                 f'<pre class="muted">{esc(pending["text"])}</pre>')
    return f"""<h2>Prove claims with your eID card</h2>
<p>Tick what the notary should attest. Only these claims are attested, each as a separate attestation that holds neither
your certificate nor your personal number. The signature you create contains your certificate: it goes to the notary
({esc(VERIFIER_URL)}) and nowhere else.</p>
<form method="post" action="/api/eid/statement">{boxes}<button>Create the statement to sign</button></form>{step2}"""


async def delivery_state(claim_id: str) -> str:
    """Where the code is: for SMS it may still be in the gateway's queue, or have been refused."""
    pending = wallet.state.get("verifications", {}).get(claim_id)
    if not pending or pending.get("kind") != "phone":
        return ""
    try:
        status, body = await verifier("GET", f"/api/verify/phone/{pending['verification_id']}/status")
    except (WalletError, aiohttp.ClientError, asyncio.TimeoutError):
        return "state unknown"
    if status != 200:
        return "state unknown"
    if body.get("delivery") == "failed":
        return f"the SMS could not be sent ({body.get('reason', 'unknown reason')}); send a new code later"
    return {"queued": "waiting for the SMS gateway to pick it up", "sent": "SMS sent"}.get(body.get("delivery", ""), "state unknown")


def devices_section() -> str:
    identity = wallet.identity
    mine = wallet.device.verify_key.to_hex()
    rows = "".join(
        f"<tr><td>{esc(d.label)}{' <b>(this device)</b>' if d.pubkey == mine else ''}</td>"
        f"<td><code>{fingerprint(d.pubkey)}</code></td><td>{esc(', '.join(d.capabilities))}</td></tr>"
        for d in identity.sigchain.get_active_devices())
    if identity.is_own:
        add = ('<form method="post" action="/api/devices/preview">Add a device: code shown on the new device '
               '<input name="code" required maxlength="16" autocomplete="off" size="14" placeholder="ABCDE-FGHJK"> '
               '<button>Look at it</button></form>')
    else:
        add = '<p class="muted">New devices are added from the wallet that holds the master key.</p>'
    return f"<h2>Devices</h2><table><tr><th>device</th><th>key fingerprint</th><th>may</th></tr>{rows}</table>{add}"


async def dashboard(request: web.Request) -> web.Response:
    if "pairing" in wallet.state:
        return await pairing_dashboard(request)
    view = state_view()
    identity = view["identity"]
    rows = []
    for c in view["claims"]:
        value = c["value"]
        shown = f"{value['given_name']} {value['family_name']}" if isinstance(value, dict) else value
        atts = "".join(f"<div>{esc(a['method'])} / {esc(a['assurance'])}{' (expired)' if a['expired'] else ''}: "
                       f"<span class='muted'>{esc(a['node_verdict'])}</span></div>" for a in c["attestations"]) or "none"
        cid = esc(c["claim_id"])
        if c["claim_type"] in CODE_CLAIMS:
            waiting = c["claim_id"] in wallet.state.get("verifications", {})
            how = "email" if c["claim_type"] == "email" else "SMS"
            actions = (f'<form method="post" action="/api/claims/{cid}/verify-email"><button>'
                       f'{"Send a new code" if waiting else f"Verify by {how}"}</button></form>')
            if waiting:
                note = await delivery_state(c["claim_id"])
                actions += (f'<form method="post" action="/api/claims/{cid}/confirm-email">Code from the {how}: '
                            f'<input name="code" required maxlength="16" autocomplete="off" size="12"> <button>Confirm</button></form>'
                            + (f'<div class="muted">{esc(note)}</div>' if note else ""))
        else:
            actions = '<span class="muted">see "Prove claims with your eID card" below</span>' if c["claim_type"] in NOTARIZABLE else ""
        siblings = [x for x in view["claims"] if x["claim_type"] == c["claim_type"] and x["rank"]]
        if len(siblings) > 1 and c["rank"]:
            badge = "<b>default</b>" if c["default"] else "#" + str(c["rank"])
            order_ui = (f"<div>{badge} "
                        + "".join(f'<form method="post" action="/api/claims/{cid}/order" style="display:inline">'
                                  f'<input type="hidden" name="how" value="{how}"><button>{label}</button></form>'
                                  for how, label in (("default", "make default"), ("up", "&#9650;"), ("down", "&#9660;"))
                                  if not (c["default"] and how in ("default", "up"))) + "</div>")
            actions = order_ui + actions
        rows.append(f"<tr><td>{esc(c['claim_type'])}<br><code>{cid[:8]}</code></td><td>{esc(c['status'])}</td>"
                    f"<td>{esc(shown)}</td><td>{atts}</td><td>{actions}</td></tr>")
    table = ("<table><tr><th>claim</th><th>status</th><th>value (private)</th><th>attestations</th><th></th></tr>"
             + "".join(rows) + "</table>") if rows else '<p class="muted">No claims yet.</p>'
    explorer = f"{NODE_URL}/explorer/#/identity/{identity}"
    eid_section = eid_form(view)
    body = f"""<p>Test identity: <code>{esc(identity)}</code> (<a href="{esc(explorer)}">see it in the explorer</a>)</p>
<h2>Claims</h2>{table}
<h3>Add a claim</h3>
<form method="post" action="/api/claims/email">Email: <input type="email" name="address" required> <button>Add</button></form>
<form method="post" action="/api/claims/birthdate">Birth date: <input type="date" name="date" required> <button>Add</button></form>
<form method="post" action="/api/claims/age"><button>Add an "I am over 18" claim</button> <span class="muted">(prove your age without your birth date)</span></form>
<form method="post" action="/api/claims/phone">Phone (international format): <input type="text" name="number" required placeholder="+359..."> <button>Add</button></form>
<form method="post" action="/api/claims/name">Legal name as on your certificate:
<input type="text" name="given" placeholder="given name" required> <input type="text" name="family" placeholder="family name" required> <button>Add</button></form>
{eid_section}
{devices_section()}
<h2>Approve a sign-in</h2>
<form method="post" action="/api/signin/preview">Sign-in address from the application:
<input type="url" name="login_url" required placeholder="{esc(NODE_URL)}/oidc/login/..."> <button>Look at it</button></form>
<p class="muted">Email and phone claims are verified by an independent service ({esc(VERIFIER_URL or 'not configured')}): it sends you a code by email or SMS, you type it here.</p>"""
    return web.Response(text=layout(body, request), content_type="text/html")


async def healthz(request: web.Request) -> web.Response:
    return web.json_response({"ok": True})


def build_app() -> web.Application:
    wallet.ensure_identity()
    app = web.Application(middlewares=[basic_auth, errors, pairing_gate], client_max_size=4 * 1024 * 1024)
    app.router.add_get("/", dashboard)
    app.router.add_get("/healthz", healthz)
    if LOCAL_APP:
        app.router.add_get("/launch", launch)
    app.router.add_get("/signin", signin_link)
    app.router.add_get("/api/state", api_state)
    app.router.add_post("/api/claims/email", api_claim_email)
    app.router.add_post("/api/claims/phone", api_claim_phone)
    app.router.add_post("/api/claims/name", api_claim_name)
    app.router.add_post("/api/claims/{id}/verify-email", api_verify_email)
    app.router.add_post("/api/claims/{id}/confirm-email", api_confirm_email)
    app.router.add_route("*", "/api/eid/statement", api_eid_statement)
    app.router.add_post("/api/eid/signature", api_eid_signature)
    app.router.add_post("/api/claims/{id}/order", api_claim_order)
    app.router.add_post("/api/claims/birthdate", api_claim_birthdate)
    app.router.add_post("/api/claims/age", api_claim_age)
    app.router.add_post("/api/signin/preview", api_signin_preview)
    app.router.add_post("/api/signin/approve", api_signin_approve)
    app.router.add_post("/api/devices/preview", api_pairing_preview)
    app.router.add_post("/api/devices/approve", api_pairing_approve)
    app.router.add_post("/api/pairing/restart", api_pairing_restart)
    app.router.add_post("/api/pairing/new-identity", api_pairing_new_identity)

    async def start(app: web.Application) -> None:
        app["publisher"] = asyncio.create_task(publish_forever(app))

    app.on_startup.append(start)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    web.run_app(build_app(), host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "4572")), print=None)
