"""Native SSO endpoints: challenge, verify, login.

See "Authentication (SSO)" in identity-system.md.

- POST /api/auth/challenge  issue an AuthRequest (RP side)
- POST /api/auth/verify     verify an AuthAssertion for any audience (RP side)
- POST /api/auth/login      verify an assertion for this node and open a session
"""

from __future__ import annotations

import json
from typing import Any

from aiohttp import web

from nodetide.api.auth.challenges import ChallengeStore, ChallengeStoreFull
from nodetide.api.auth.sessions import SessionStore
from nodetide.api.models import APIError
from nodetide.core.auth import (
    CLOCK_SKEW,
    DEFAULT_REQUEST_LIFETIME,
    AuthRequest,
    AuthResult,
    choose_sigchain,
    verify_assertion,
    verify_assertion_with_state,
)
from nodetide.core.dns_source import dns_domains, dns_point
from nodetide.core.identity import Sigchain
from nodetide.core.state import StateError, VerifiedState, verify_state
from nodetide.core.storage import Storage

MAX_AUD_LENGTH = 512
MAX_CALLBACK_LENGTH = 2048
MAX_CLAIMS = 16
SESSION_LIFETIME = 3600

# Verification failures that mean "retry with fresher state" rather than "reject".
_STALE = "unknown_chain_head"


def _error(code: str, message: str, status: int, details: dict | None = None) -> web.Response:
    return web.json_response(
        APIError(error=code, message=message, code=status, details=details).to_dict(),
        status=status,
    )


async def _json_body(request: web.Request) -> dict[str, Any]:
    """Parse an optional JSON object body. Raises ValueError if malformed."""
    text = await request.text()
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError("Invalid JSON") from e
    if not isinstance(data, dict):
        raise ValueError("Body must be a JSON object")
    return data


def _resolve_sigchain(
    storage: Storage,
    identity: str,
    supplied: Any,
) -> tuple[Sigchain | None, web.Response | None]:
    """Pick the sigchain to verify against.

    The RP may supply a chain (self-authenticating: identity = hash(genesis)),
    and/or hold one in storage. When both exist the longer one wins, so a
    caller cannot hide a revocation by supplying an older prefix. Divergent
    chains are a fork and are rejected.
    """
    stored = storage.get_sigchain(identity)

    provided: Sigchain | None = None
    if supplied is not None:
        if not isinstance(supplied, list):
            return None, _error("invalid_request", "sigchain must be a list of events", 400)
        try:
            provided = Sigchain.from_list(supplied)
        except Exception:
            return None, _error("invalid_request", "Malformed sigchain", 400)

    chain, conflict = choose_sigchain(stored, provided)
    if conflict:
        return None, _error("conflict", "Supplied sigchain conflicts with stored sigchain", 409)
    if chain is None:
        return None, _error("not_found", f"Identity {identity} not found", 404)
    return chain, None


async def _state_for(request: web.Request, identity: str, data: dict[str, Any], chain: Sigchain | None) -> VerifiedState | None:
    """A verified state of `identity` to check the assertion against when no (fresh enough) sigchain is at hand: the one the
    caller supplied, else the one published in DNS at a `dns:` point of the identity's own chain, or named by the caller."""
    supplied = data.get("state")
    if isinstance(supplied, dict):
        try:
            return verify_state(supplied, expect_identity=identity)
        except StateError:
            pass
    domains: list[str] = []
    if chain is not None:
        points: list[str] = []
        for event in chain.events:
            points = getattr(event, "distribution_points", None) or points
        domains = dns_domains(points)
    hint = data.get("dns")
    if isinstance(hint, str) and (domain := dns_point(hint if hint.lower().startswith("dns:") else f"dns:{hint}")):
        if domain not in domains:
            domains.append(domain)
    source = request.app.get("dns_state")
    if source is None:
        return None
    for domain in domains[:3]:
        state = await source.fetch(domain, identity)
        if state is not None:
            return state
    return None


async def _process_assertion(
    request: web.Request,
    forced_aud: str | None = None,
) -> tuple[web.Response | None, AuthResult | None]:
    """Shared verification for /verify and /login.

    Returns (error_response, None) or (None, result). The challenge nonce is
    consumed only after the assertion verified successfully.
    """
    storage: Storage = request.app["storage"]
    challenges: ChallengeStore = request.app["challenge_store"]

    try:
        data = await _json_body(request)
    except ValueError as e:
        return _error("invalid_request", str(e), 400), None

    assertion = data.get("assertion")
    if not isinstance(assertion, dict):
        return _error("invalid_request", "Missing assertion", 400), None
    nonce = assertion.get("nonce")
    identity = assertion.get("identity")
    if not isinstance(nonce, str) or not isinstance(identity, str):
        return _error("invalid_request", "Assertion needs string nonce and identity", 400), None

    auth_request = challenges.peek(nonce)
    if auth_request is None:
        return _error("unknown_challenge", "Challenge is unknown, already used, or expired", 401), None
    if forced_aud is not None and auth_request.aud != forced_aud:
        return _error("wrong_audience", "Challenge was not issued for this node", 401), None

    chain, err = _resolve_sigchain(storage, identity, data.get("sigchain"))
    if err is not None and err.status != 404:
        return err, None

    # With a chain it is the chain that decides. Without one, or when ours is behind the signer's, a signed state of the
    # identity (supplied by the caller or published in DNS) can stand in for authentication.
    result = verify_assertion(assertion, chain, expected_aud=auth_request.aud) if chain is not None else None
    if result is None or result.code == _STALE:
        state = await _state_for(request, identity, data, chain)
        if state is not None:
            via_state = verify_assertion_with_state(assertion, state, expected_aud=auth_request.aud)
            if via_state.ok or result is None:
                result = via_state
    if result is None:
        assert err is not None
        return err, None
    if result.ok and assertion["exp"] > auth_request.expires_at + CLOCK_SKEW:
        result = AuthResult.fail("invalid_assertion", "Assertion outlives its challenge")

    if not result.ok:
        if result.code == _STALE:
            return _error(
                "stale_state",
                result.error or "Stale sigchain",
                409,
                details={"head_hash": chain.head_hash, "length": len(chain.events)} if chain is not None else None,
            ), None
        return _error(result.code or "invalid_assertion", result.error or "Invalid", 401), None

    if not challenges.consume(nonce):
        return _error("unknown_challenge", "Challenge is unknown, already used, or expired", 401), None
    return None, result


async def challenge_handler(request: web.Request) -> web.Response:
    """POST /api/auth/challenge - issue an AuthRequest.

    Body (all optional if the node has a configured audience):
        {"aud": "https://app.example.com", "callback": "...",
         "claims": ["name"], "expires_in": 300}
    """
    challenges: ChallengeStore = request.app["challenge_store"]

    try:
        data = await _json_body(request)
    except ValueError as e:
        return _error("invalid_request", str(e), 400)

    aud = data.get("aud") or request.app.get("auth_audience")
    if not isinstance(aud, str) or not aud:
        return _error("invalid_request", "aud is required", 400)
    if len(aud) > MAX_AUD_LENGTH:
        return _error("invalid_request", "aud too long", 400)

    callback = data.get("callback")
    if callback is not None:
        if not isinstance(callback, str) or len(callback) > MAX_CALLBACK_LENGTH:
            return _error("invalid_request", "Invalid callback", 400)
        if not callback.startswith(aud.rstrip("/") + "/") and callback != aud:
            return _error("invalid_request", "callback must be under aud", 400)

    claims = data.get("claims") or []
    if (
        not isinstance(claims, list)
        or len(claims) > MAX_CLAIMS
        or not all(isinstance(c, str) for c in claims)
    ):
        return _error("invalid_request", "claims must be a list of strings", 400)

    expires_in = data.get("expires_in", DEFAULT_REQUEST_LIFETIME)
    if isinstance(expires_in, bool) or not isinstance(expires_in, int) or expires_in < 1:
        return _error("invalid_request", "expires_in must be a positive integer", 400)

    auth_request = AuthRequest.new(
        aud=aud, lifetime=expires_in, callback=callback, claims=claims
    )
    try:
        challenges.add(auth_request)
    except ChallengeStoreFull:
        return _error("rate_limited", "Too many outstanding challenges", 429)

    return web.json_response(auth_request.to_dict(), status=201)


async def verify_handler(request: web.Request) -> web.Response:
    """POST /api/auth/verify - verify an AuthAssertion.

    Body: {"assertion": {...}, "sigchain": [...]}  (sigchain optional if stored)
    """
    error, result = await _process_assertion(request)
    if error is not None:
        return error
    assert result is not None

    return web.json_response({
        "valid": True,
        "identity": result.identity,
        "device": result.device,
        "claims": result.claims,  # self-asserted; not verified by this endpoint
    })


async def login_handler(request: web.Request) -> web.Response:
    """POST /api/auth/login - verify an assertion for this node and open a session.

    The challenge must have been issued for the node's own audience
    (NODETIDE_AUTH_AUDIENCE). Returns a session token usable as a Bearer token.
    """
    audience = request.app.get("auth_audience")
    if not audience:
        return _error("not_configured", "Login audience is not configured", 501)

    error, result = await _process_assertion(request, forced_aud=audience)
    if error is not None:
        return error
    assert result is not None and result.identity and result.device

    session_store: SessionStore = request.app["session_store"]
    session = session_store.create(
        identity=result.identity,
        device_pubkey=result.device,
        expires_in=SESSION_LIFETIME,
    )
    body: dict[str, Any] = {
        "token": session.token,
        "expires_at": session.expires_at,
        "identity": session.identity,
    }

    casbin_auth = request.app.get("casbin_auth")
    if casbin_auth is not None:
        body["jwt"] = casbin_auth.create_token(session.identity)

    return web.json_response(body, status=201)


def setup_native_auth_routes(app: web.Application) -> None:
    """Register the native auth routes."""
    app.router.add_post("/api/auth/challenge", challenge_handler)
    app.router.add_post("/api/auth/verify", verify_handler)
    app.router.add_post("/api/auth/login", login_handler)
