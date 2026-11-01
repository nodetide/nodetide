"""HTTP API for claims, claim documents and attestations."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from aiohttp import web

from nodetide.api.models import APIError
from nodetide.core.auth import choose_sigchain
from nodetide.core.claims import (
    Attestation,
    AttestationRevocation,
    ClaimDocument,
    ClaimError,
    publication_signing_input,
    verify_attestation,
    verify_revocation,
)
from nodetide.core.crypto import VerifyKey
from nodetide.core.identity import DeviceCapability, Sigchain
from nodetide.core.storage import Storage

HASH_LEN = 64
MAX_ATTESTATIONS_PER_CLAIM = 50
PUBLICATION_WINDOW = 300


def error(code: str, message: str, status: int, details: dict | None = None) -> web.Response:
    return web.json_response(
        APIError(error=code, message=message, code=status, details=details).to_dict(), status=status
    )


async def read_object(request: web.Request) -> dict[str, Any] | web.Response:
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return error("invalid_request", "Invalid JSON", 400)
    if not isinstance(data, dict):
        return error("invalid_request", "Body must be a JSON object", 400)
    return data


def resolve_chain(
    storage: Storage, identity: str, supplied: Any
) -> tuple[Sigchain | None, web.Response | None]:
    """Stored and/or supplied sigchain for an identity (longer one wins; forks rejected)."""
    provided = None
    if supplied is not None:
        if not isinstance(supplied, list):
            return None, error("invalid_request", "sigchain must be a list of events", 400)
        try:
            provided = Sigchain.from_list(supplied)
        except Exception:
            return None, error("invalid_request", "Malformed sigchain", 400)
    chain, conflict = choose_sigchain(storage.get_sigchain(identity), provided)
    if conflict:
        return None, error("conflict", "Supplied sigchain conflicts with the stored one", 409)
    if chain is None:
        return None, error("not_found", f"Identity {identity} is not known to this node", 404)
    return chain, None


# --- claims ---------------------------------------------------------------------------


async def list_claims(request: web.Request) -> web.Response:
    """GET /identities/{hash}/claims - claims on the chain, with attestations and published values."""
    storage: Storage = request.app["storage"]
    identity = request.match_info["hash"]
    chain = storage.get_sigchain(identity)
    if chain is None:
        return error("not_found", f"Identity {identity} not found", 404)

    now = int(time.time())
    documents = storage.get_claim_documents(identity)
    attestations = storage.list_attestations(subject=identity, limit=500)
    claims = []
    for record in chain.get_claims():
        atts = []
        for item in attestations:
            att = item["attestation"]
            if att["claim_id"] != record.claim_id:
                continue
            atts.append({
                "attestation_id": item["attestation_id"],
                "issuer": att.get("issuer"),
                "method": att["method"],
                "assurance": att["assurance"],
                "issued_at": att["issued_at"],
                "expires_at": att["expires_at"],
                "expired": now > att["expires_at"],
                "revoked": item["revoked_at"] is not None,
            })
        claims.append({
            "claim_id": record.claim_id,
            "claim_type": record.claim_type,
            "commitment": record.commitment,
            "status": record.status(now),
            "created_at": record.created_at,
            "expires": record.expires,
            "revoked_at": record.revoked_at,
            "revoke_reason": record.revoke_reason,
            "event_hash": record.event_hash,
            "document": documents.get(record.claim_id),  # present only if the holder published it
            "attestations": atts,
        })
    return web.json_response({"identity": identity, "claims": claims})


async def post_document(request: web.Request) -> web.Response:
    """POST /claims/documents - publish or unpublish a claim document (signed by the holder).

    Body: {"action": "publish"|"unpublish", "document": {...}, "issued_at": int,
           "signed_by": <pubkey hex>, "sig": <hex>}
    Publishing reveals the claim's value to everyone, so it needs the holder's signature.
    """
    storage: Storage = request.app["storage"]
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data

    action = data.get("action")
    document = data.get("document")
    issued_at, signed_by, sig = data.get("issued_at"), data.get("signed_by"), data.get("sig")
    if action not in ("publish", "unpublish") or not isinstance(document, dict):
        return error("invalid_request", "action and document are required", 400)
    if isinstance(issued_at, bool) or not isinstance(issued_at, int) or not isinstance(signed_by, str) \
            or not isinstance(sig, str):
        return error("invalid_request", "issued_at, signed_by and sig are required", 400)
    if abs(int(time.time()) - issued_at) > PUBLICATION_WINDOW:
        return error("invalid_request", "issued_at is too far from the current time", 400)

    identity, claim_id = document.get("identity"), document.get("claim_id")
    if not isinstance(identity, str) or not isinstance(claim_id, str):
        return error("invalid_request", "document needs identity and claim_id", 400)
    chain = storage.get_sigchain(identity)
    if chain is None:
        return error("not_found", f"Identity {identity} not found", 404)
    valid, err = chain.verify(storage.get_sigchain)
    if not valid:
        return error("invalid_sigchain", err or "Invalid sigchain", 400)

    # The signer must be the master or a current device holding manage_claims.
    allowed = signed_by == chain.get_current_master_key() or any(
        d.pubkey == signed_by and DeviceCapability.MANAGE_CLAIMS.value in d.capabilities
        for d in chain.get_active_devices()
    )
    if not allowed:
        return error("forbidden", "Signing key may not manage this identity's claims", 403)
    try:
        signature_ok = VerifyKey.from_hex(signed_by).verify_hex(
            publication_signing_input(action, document, issued_at), sig
        )
    except Exception:
        signature_ok = False
    if not signature_ok:
        return error("invalid_signature", "Invalid signature", 401)

    existing = storage.get_claim_documents(identity).get(claim_id)
    if existing and issued_at <= existing["published_at"]:
        return error("stale_state", "A newer publication for this claim exists", 409)

    if action == "unpublish":
        removed = storage.delete_claim_document(identity, claim_id)
        return web.json_response({"unpublished": removed})

    try:
        doc = ClaimDocument.from_dict(document)
    except ClaimError as e:
        return error("invalid_request", str(e), 400)
    record = chain.get_claim(claim_id)
    if record is None or not doc.matches(record):
        return error("claim_mismatch", "Document does not match the claim on the chain", 400)
    status = record.status()
    if status != "active":
        return error("claim_not_active", f"The claim is {status}", 409)
    storage.save_claim_document(identity, claim_id, doc.claim_type, doc.value, doc.salt, issued_at)
    return web.json_response({"published": True, "claim_id": claim_id}, status=201)


# --- attestations ----------------------------------------------------------------------------


_STATUS_FOR_CODE = {
    "unknown_chain_head": 409,
    "unknown_issuer": 404,
    "bad_signature": 401,
    "issuer_key_not_authorized": 403,
}


async def post_attestation(request: web.Request) -> web.Response:
    """POST /attestations - store a verified attestation.

    Body: {"attestation": {...}, "subject_sigchain": [...]?, "issuer_sigchain": [...]?}
    """
    storage: Storage = request.app["storage"]
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data
    try:
        att = Attestation.from_dict(data.get("attestation"))
    except ClaimError as e:
        return error("invalid_request", str(e), 400)
    if att.proof is not None:
        # A proof embeds the signer's certificate, which carries personal identifiers.
        return error(
            "proof_not_publishable",
            "Attestations with an embedded proof are shown to relying parties, not published",
            422,
        )

    subject_chain, err = resolve_chain(storage, att.subject, data.get("subject_sigchain"))
    if err is not None:
        return err
    issuer_chain = None
    if att.issuer is not None:
        issuer_chain, err = resolve_chain(storage, att.issuer, data.get("issuer_sigchain"))
        if err is not None:
            return err

    check = verify_attestation(att, subject_chain, issuer_chain, resolve=storage.get_sigchain)
    if not check.ok:
        status = _STATUS_FOR_CODE.get(check.code or "", 422)
        details = {"head_hash": subject_chain.head_hash} if check.code == "unknown_chain_head" else None
        return error(check.code or "invalid_attestation", check.error or "Invalid attestation", status, details)

    if storage.get_attestation_revocation(att.id) is not None:
        return error("revoked", "The issuer has revoked this attestation", 409)
    existing = storage.list_attestations(subject=att.subject, claim_id=att.claim_id, limit=MAX_ATTESTATIONS_PER_CLAIM + 1)
    if len(existing) >= MAX_ATTESTATIONS_PER_CLAIM and not any(e["attestation_id"] == att.id for e in existing):
        return error("rate_limited", "Too many attestations for this claim", 429)

    storage.save_attestation(att.id, att.to_dict())
    return web.json_response({"attestation_id": att.id, "accepted": True}, status=201)


async def list_attestations(request: web.Request) -> web.Response:
    """GET /attestations?subject=&claim_id=&issuer="""
    storage: Storage = request.app["storage"]
    q = request.query
    if not any(q.get(k) for k in ("subject", "claim_id", "issuer")):
        return error("invalid_request", "Give subject, claim_id or issuer", 400)
    try:
        limit = max(1, min(int(q.get("limit", "50")), 200))
    except ValueError:
        return error("invalid_request", "limit must be an integer", 400)
    items = storage.list_attestations(q.get("subject"), q.get("claim_id"), q.get("issuer"), limit)
    return web.json_response({"attestations": items})


async def get_attestation(request: web.Request) -> web.Response:
    storage: Storage = request.app["storage"]
    attestation_id = request.match_info["id"]
    body = storage.get_attestation(attestation_id)
    if body is None:
        return error("not_found", "Attestation not found", 404)
    revocation = storage.get_attestation_revocation(attestation_id)
    return web.json_response({
        "attestation_id": attestation_id,
        "attestation": body,
        "revoked_at": revocation["issued_at"] if revocation else None,
        "revoke_reason": revocation.get("reason") if revocation else None,
    })


async def post_revocation(request: web.Request) -> web.Response:
    """POST /attestations/revocations - {"revocation": {...}, "issuer_sigchain": [...]?}"""
    storage: Storage = request.app["storage"]
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data
    try:
        rev = AttestationRevocation.from_dict(data.get("revocation"))
    except ClaimError as e:
        return error("invalid_request", str(e), 400)

    issuer_chain, err = resolve_chain(storage, rev.issuer, data.get("issuer_sigchain"))
    if err is not None:
        return err
    check = verify_revocation(rev, issuer_chain, resolve=storage.get_sigchain)
    if not check.ok:
        return error(check.code or "invalid_revocation", check.error or "Invalid revocation",
                     _STATUS_FOR_CODE.get(check.code or "", 422))

    stored = storage.get_attestation(rev.attestation_id)
    if stored is not None and stored.get("issuer") != rev.issuer:
        return error("forbidden", "Only the issuer can revoke an attestation", 403)
    storage.save_attestation_revocation(rev.attestation_id, rev.to_dict())
    return web.json_response({"revoked": True, "attestation_id": rev.attestation_id}, status=201)


async def verify_claim(request: web.Request) -> web.Response:
    """POST /claims/verify - check an attestation (and optionally a disclosed claim value).

    Stateless: nothing is stored, so this is safe for attestations that embed a
    signer's certificate. Body: {"attestation": {...}, "document": {...}?,
    "subject_sigchain": [...]?, "issuer_sigchain": [...]?,
    "name_match": "exact"|"transliterated"|"approximate"?}
    Whether the issuer or authority is *acceptable* is the caller's policy;
    name_match is the weakest legal-name match to accept (default transliterated).
    """
    storage: Storage = request.app["storage"]
    data = await read_object(request)
    if isinstance(data, web.Response):
        return data
    try:
        att = Attestation.from_dict(data.get("attestation"))
        document = ClaimDocument.from_dict(data["document"]) if data.get("document") is not None else None
    except ClaimError as e:
        return error("invalid_request", str(e), 400)

    subject_chain, err = resolve_chain(storage, att.subject, data.get("subject_sigchain"))
    if err is not None:
        return err
    issuer_chain = None
    if att.issuer is not None:
        issuer_chain, err = resolve_chain(storage, att.issuer, data.get("issuer_sigchain"))
        if err is not None:
            return err

    def fail(code: str, message: str, status: int = 422) -> web.Response:
        return web.json_response({"valid": False, "code": code, "error": message}, status=status)

    # Proof checks may use the network (revocation); keep that off the event loop.
    check = await asyncio.get_running_loop().run_in_executor(
        None, lambda: verify_attestation(att, subject_chain, issuer_chain, resolve=storage.get_sigchain)
    )
    if not check.ok:
        return fail(check.code or "invalid_attestation", check.error or "Invalid attestation",
                    409 if check.code == "unknown_chain_head" else 422)
    if att.proof is None:
        revocation = storage.get_attestation_revocation(att.id)
        if revocation is not None:
            return fail("revoked", "The issuer has revoked this attestation", 409)

    result: dict[str, Any] = {
        "valid": True,
        "attestation_id": att.id,
        "subject": att.subject,
        "claim_id": att.claim_id,
        "claim_type": att.claim_type,
        "method": att.method,
        "assurance": att.assurance,
        "issuer": att.issuer,
        "issued_at": att.issued_at,
        "expires_at": att.expires_at,
        "value_checked": False,
    }

    if document is not None:
        record = subject_chain.get_claim(att.claim_id)
        if document.identity != att.subject or not document.matches(record):
            return fail("claim_mismatch", "The document is not the one this attestation covers")
        result["value_checked"] = True
        if att.proof is not None and att.claim_type == "legal_name":
            from nodetide.eidas.verify import check_legal_name

            leniency = data.get("name_match", "transliterated")
            if not isinstance(leniency, str):
                return error("invalid_request", "name_match must be a string", 400)
            name = check_legal_name(att, document, leniency)
            if not name.ok:
                return fail("name_mismatch", name.reason or "The name does not match the certificate")
            result["name_match"] = name.how
    return web.json_response(result)


def setup_claims_routes(app: web.Application) -> None:
    app.router.add_post("/api/claims/verify", verify_claim)
    app.router.add_get("/api/identities/{hash}/claims", list_claims)
    app.router.add_post("/api/claims/documents", post_document)
    app.router.add_post("/api/attestations", post_attestation)
    app.router.add_get("/api/attestations", list_attestations)
    app.router.add_post("/api/attestations/revocations", post_revocation)
    app.router.add_get("/api/attestations/{id}", get_attestation)
