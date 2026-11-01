"""HTTP API of a claim verification service (currently: email). Served by nodetide.verifiers.service, not by nodes."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import time

from aiohttp import web

from nodetide.api.auth.challenges import ChallengeStore
from nodetide.api.claims import error, read_object, resolve_chain
from nodetide.core.auth import CLOCK_SKEW, verify_assertion
from nodetide.core.claims import ClaimDocument, ClaimError
from nodetide.core.identity import Sigchain
from nodetide.eidas.notary_statement import parse_notary_statement
from nodetide.core.storage import Storage
from nodetide.verifiers import CodeVerifier, SmsOutbox, VerificationError
from nodetide.verifiers.eid_notary import EidNotary

PURPOSE = "claim_verification"
EID_PURPOSE = "eid_attestation"
MAX_SIGNATURE_B64 = 256 * 1024 * 4 // 3 + 8


def _verifier(request: web.Request) -> CodeVerifier | None:
    return request.app.get("verifiers", {}).get(request.match_info.get("kind", ""))


async def _authenticate(request: web.Request, data: dict, identity: str) -> tuple[Sigchain, dict] | web.Response:
    """Prove the caller controls a key of `identity` for THIS service: returns (chain, signed claims) or an error."""
    audience = request.app.get("auth_audience")
    storage: Storage = request.app["storage"]
    challenges: ChallengeStore = request.app["challenge_store"]
    assertion = data.get("assertion")
    if not isinstance(assertion, dict) or not isinstance(assertion.get("nonce"), str):
        return error("invalid_request", "An assertion with a nonce is required", 400)
    if assertion.get("identity") != identity:
        return error("invalid_request", "The assertion is for a different identity", 400)
    challenge = challenges.peek(assertion["nonce"])
    if challenge is None:
        return error("unknown_challenge", "Challenge is unknown, already used, or expired", 401)
    if challenge.aud != audience:
        return error("wrong_audience", "Challenge was not issued for this service", 401)
    chain, err = resolve_chain(storage, identity, data.get("sigchain"))
    if err is not None:
        return err
    result = verify_assertion(assertion, chain, expected_aud=audience)
    if result.ok and assertion["exp"] > challenge.expires_at + CLOCK_SKEW:
        return error("invalid_assertion", "Assertion outlives its challenge", 401)
    if not result.ok:
        if result.code == "unknown_chain_head":
            return error("stale_state", result.error or "Stale sigchain", 409, {"head_hash": chain.head_hash})
        return error(result.code or "invalid_assertion", result.error or "Invalid assertion", 401)
    return chain, result.claims


async def issuer_info(request: web.Request) -> web.Response:
    """GET /verify/issuer - who issues attestations here, and for which claims."""
    verifiers: dict[str, CodeVerifier] = request.app.get("verifiers", {})
    notary: EidNotary | None = request.app.get("notary")
    if not verifiers and notary is None:
        return error("not_configured", "This service does not verify claims", 404)
    issuer = request.app["issuer"]
    return web.json_response({
        "issuer": issuer.identity_hash,
        "name": issuer.name,
        "audience": request.app.get("auth_audience"),
        # so a holder can present its attestations anywhere without a lookup
        "sigchain": issuer.identity.sigchain.to_list(),
        # an organization with owners is checked against their chains
        "owner_sigchains": {
            o["identity"]: chain.to_list()
            for o in (issuer.identity.sigchain.get_owners() or [])
            if (chain := request.app["storage"].get_sigchain(o["identity"])) is not None
        },
        "methods": [{
            "method": v.method,
            "claim_type": v.claim_type,
            "assurance": v.assurance,
            "start": f"/api/verify/{kind}/start",
            "confirm": f"/api/verify/{kind}/confirm",
        } for kind, v in verifiers.items()] + ([notary.describe()] if notary is not None else []),
    })


async def start(request: web.Request) -> web.Response:
    """POST /verify/{email|phone}/start - {"document": {...}, "assertion": {...}, "sigchain": [...]?}

    The assertion is an AuthAssertion for this service's audience (challenge from
    /auth/challenge) whose signed claims bind it to this claim:
    {"purpose": "claim_verification", "claim_id": "<claim id>"}.
    """
    verifier = _verifier(request)
    audience = request.app.get("auth_audience")
    if verifier is None or not audience:
        return error("not_configured", "This kind of verification is not enabled", 404)

    challenges: ChallengeStore = request.app["challenge_store"]
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data

    try:
        document = ClaimDocument.from_dict(data.get("document"))
    except ClaimError as e:
        return error("invalid_request", str(e), 400)
    authenticated = await _authenticate(request, data, document.identity)
    if isinstance(authenticated, web.Response):
        return authenticated
    chain, signed = authenticated
    if signed.get("purpose") != PURPOSE or signed.get("claim_id") != document.claim_id:
        return error("assertion_not_bound", "The assertion must be signed for this claim's verification", 401)
    if not challenges.consume(data["assertion"]["nonce"]):
        return error("unknown_challenge", "Challenge is unknown, already used, or expired", 401)

    try:
        verification_id, expires_at = await verifier.start(document, chain)
    except VerificationError as e:
        return error(e.code, e.message, e.status)
    return web.json_response({
        "verification_id": verification_id,
        "expires_at": expires_at,
        "message": "A verification code was sent." if verifier.claim_type == "email"
        else "A verification code was queued for SMS.",
    }, status=202)


async def eid_attest(request: web.Request) -> web.Response:
    """POST /verify/eid/attest - the eID notary.

    {"statement": "<notary statement text>", "signature": "<base64 detached CAdES>",
     "documents": [{claim document}, ...], "assertion": {...}, "sigchain": [...]?}

    The assertion's signed claims MUST be {"purpose": "eid_attestation", "statement_sha256": "<sha256 hex of the
    statement text>"}: the request comes from a key of the identity, for exactly this statement. The signature embeds
    the certificate; it goes to this service only, is used for this request and is not kept.
    """
    notary: EidNotary | None = request.app.get("notary")
    if notary is None or not request.app.get("auth_audience"):
        return error("not_configured", "eID attestation is not enabled", 404)
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data
    statement, signature, documents = data.get("statement"), data.get("signature"), data.get("documents")
    if not isinstance(statement, str) or not isinstance(signature, str) or not isinstance(documents, list) or len(documents) > 5:
        return error("invalid_request", "statement, signature and documents are required", 400)
    if len(signature) > MAX_SIGNATURE_B64:
        return error("invalid_request", "The signature is too large", 400)
    try:
        der = base64.b64decode(signature, validate=True)
        docs = [ClaimDocument.from_dict(d) for d in documents]
        identity = parse_notary_statement(statement).identity
    except (binascii.Error, ValueError, ClaimError) as e:
        return error("invalid_request", str(e), 400)

    authenticated = await _authenticate(request, data, identity)
    if isinstance(authenticated, web.Response):
        return authenticated
    chain, signed = authenticated
    if signed.get("purpose") != EID_PURPOSE or signed.get("statement_sha256") != hashlib.sha256(statement.encode()).hexdigest():
        return error("assertion_not_bound", "The assertion must be signed for exactly this statement", 401)
    if not request.app["challenge_store"].consume(data["assertion"]["nonce"]):
        return error("unknown_challenge", "Challenge is unknown, already used, or expired", 401)
    try:
        attestations = await notary.attest(statement, der, docs, chain)
    except VerificationError as e:
        return error(e.code, e.message, e.status)
    return web.json_response({"attestations": [a.to_dict() for a in attestations]}, status=201)


async def confirm(request: web.Request) -> web.Response:
    """POST /verify/{email|phone}/confirm - {"verification_id": "...", "code": "..."}"""
    verifier = _verifier(request)
    if verifier is None:
        return error("not_configured", "This kind of verification is not enabled", 404)
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data
    verification_id, code = data.get("verification_id"), data.get("code")
    if not isinstance(verification_id, str) or not isinstance(code, str) or len(code) > 32:
        return error("invalid_request", "verification_id and code are required", 400)
    try:
        attestation = verifier.confirm(verification_id, code)
    except VerificationError as e:
        return error(e.code, e.message, e.status)
    return web.json_response(
        {"attestation_id": attestation.id, "attestation": attestation.to_dict()}, status=201
    )


async def delivery_status(request: web.Request) -> web.Response:
    """GET /verify/{email|phone}/{verification_id}/status - did the code leave? (the id is the capability)"""
    verifier = _verifier(request)
    if verifier is None:
        return error("not_configured", "This kind of verification is not enabled", 404)
    try:
        return web.json_response(verifier.delivery_status(request.match_info["verification_id"]))
    except VerificationError as e:
        return error(e.code, e.message, e.status)


# --- SMS gateway: a script next to a modem fetches the queue and reports back ---------------------------


MAX_WAIT = 30


def _gateway_authorized(request: web.Request) -> bool:
    expected: bytes | None = request.app.get("gateway_token_digest")
    header = request.headers.get("Authorization", "")
    if expected is None or not header.lower().startswith("bearer "):
        return False
    supplied = hashlib.sha256(header[7:].strip().encode()).digest()
    return hmac.compare_digest(supplied, expected)


def _gateway_denied(request: web.Request) -> web.Response | None:
    outbox: SmsOutbox | None = request.app.get("sms_outbox")
    if outbox is None or request.app.get("gateway_token_digest") is None:
        return error("not_configured", "No SMS gateway is configured", 404)
    if not _gateway_authorized(request):
        resp = error("unauthorized", "Gateway token required", 401)
        resp.headers["WWW-Authenticate"] = 'Bearer realm="sms-gateway"'
        return resp
    return None


async def gateway_pending(request: web.Request) -> web.Response:
    """GET /gateway/sms/pending?wait=25&max=5 - long poll for messages to send."""
    denied = _gateway_denied(request)
    if denied is not None:
        return denied
    outbox: SmsOutbox = request.app["sms_outbox"]
    try:
        wait = min(max(float(request.query.get("wait", 20)), 0.0), MAX_WAIT)
        limit = min(max(int(request.query.get("max", 5)), 1), 10)
    except ValueError:
        return error("invalid_request", "wait and max must be numbers", 400)
    deadline = time.monotonic() + wait
    while True:
        jobs = outbox.lease(limit)
        remaining = deadline - time.monotonic()
        if jobs or remaining <= 0:
            break
        await outbox.wait_for_work(remaining)
    return web.json_response({"messages": [
        {"id": j.id, "to": j.to, "text": j.text, "expires_at": int(j.expires_at)} for j in jobs]})


async def gateway_result(request: web.Request) -> web.Response:
    """POST /gateway/sms/{id}/result - {"status": "sent"|"failed"|"rejected", "reason": "..."}"""
    denied = _gateway_denied(request)
    if denied is not None:
        return denied
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data
    status, reason = data.get("status"), data.get("reason", "")
    if status not in ("sent", "failed", "rejected") or not isinstance(reason, str):
        return error("invalid_request", "status must be sent, failed or rejected", 400)
    if not request.app["sms_outbox"].report(request.match_info["id"], status, reason):
        return error("unknown_message", "Unknown or already reported message", 404)
    return web.json_response({"ok": True})


def setup_verifier_routes(app: web.Application) -> None:
    app.router.add_get("/api/verify/issuer", issuer_info)
    app.router.add_post("/api/verify/eid/attest", eid_attest)
    app.router.add_post("/api/verify/{kind}/start", start)
    app.router.add_post("/api/verify/{kind}/confirm", confirm)
    app.router.add_get("/api/verify/{kind}/{verification_id}/status", delivery_status)
    app.router.add_get("/api/gateway/sms/pending", gateway_pending)
    app.router.add_post("/api/gateway/sms/{id}/result", gateway_result)
