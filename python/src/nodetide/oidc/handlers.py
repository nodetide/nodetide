"""aiohttp routes for the OIDC bridge."""

from __future__ import annotations

import base64
import dataclasses
import json
import re
import secrets
from typing import Any
from urllib.parse import unquote_plus

from aiohttp import web

from nodetide.core.storage import Storage
from nodetide.core.relying_party import ClaimRule
from nodetide.oidc.config import OIDCConfig
from nodetide.oidc.fetcher import FetchFn
from nodetide.oidc.pages import csp, render_error_page, render_login_page
from nodetide.oidc.provider import OIDCProvider, TokenError, add_query

_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_PAGE_HEADERS = {
    **_NO_STORE,
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


def _provider(request: web.Request) -> OIDCProvider:
    return request.app["oidc"]


def _json(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> web.Response:
    return web.json_response(data, status=status, headers={**_NO_STORE, **(headers or {})})


def _redirect(location: str) -> web.Response:
    return web.Response(status=302, headers={"Location": location, **_NO_STORE})


def _html_error(message: str, status: int = 400) -> web.Response:
    return web.Response(
        text=render_error_page(message),
        status=status,
        content_type="text/html",
        headers=_PAGE_HEADERS,
    )


async def discovery(request: web.Request) -> web.Response:
    return web.json_response(
        _provider(request).discovery_document(), headers={"Cache-Control": "public, max-age=300"}
    )


async def jwks(request: web.Request) -> web.Response:
    return web.json_response(
        _provider(request).key.jwks(), headers={"Cache-Control": "public, max-age=300"}
    )


async def authorize(request: web.Request) -> web.Response:
    """GET /oidc/authorize - start a sign-in attempt."""
    provider = _provider(request)
    q = request.query

    for name in (
        "client_id", "redirect_uri", "state", "nonce", "scope", "response_type",
        "code_challenge", "code_challenge_method", "login_hint",
    ):
        if len(q.getall(name, [])) > 1:
            return _html_error(f"Duplicate parameter: {name}")

    # Until client and redirect_uri are validated, never redirect (open redirect).
    client = provider.config.clients.get(q.get("client_id", ""))
    redirect_uri = q.get("redirect_uri", "")
    if client is None or redirect_uri not in client.redirect_uris:
        return _html_error("Unknown application or redirect address.")

    state = q.get("state")

    def reject(error: str, description: str) -> web.Response:
        return _redirect(
            add_query(redirect_uri, {"error": error, "error_description": description, "state": state})
        )

    if q.get("response_type") != "code":
        return reject("unsupported_response_type", "Only response_type=code is supported")
    scope = q.get("scope", "")
    if "openid" not in scope.split():
        return reject("invalid_scope", "The openid scope is required")

    challenge = q.get("code_challenge")
    if challenge:
        if q.get("code_challenge_method") != "S256":
            return reject("invalid_request", "code_challenge_method must be S256")
        if not _CHALLENGE_RE.match(challenge):
            return reject("invalid_request", "Invalid code_challenge")
    elif client.is_public:
        return reject("invalid_request", "PKCE (code_challenge) is required")

    attempt = provider.create_attempt(
        client=client,
        redirect_uri=redirect_uri,
        state=state,
        oidc_nonce=q.get("nonce"),
        scope=scope,
        code_challenge=challenge,
        login_hint=q.get("login_hint"),
    )
    if attempt is None:
        return reject("temporarily_unavailable", "Too many sign-ins in progress; try again shortly")

    # The secret rides in the URL fragment so it is never sent to a server,
    # logged, or visible to someone who only saw the QR code / deep link.
    return _redirect(f"/oidc/login/{attempt.id}#{attempt.secret}")


async def login_page(request: web.Request) -> web.Response:
    """GET /oidc/login/{id} - the page the user's browser shows."""
    provider = _provider(request)
    attempt = provider.get_attempt(request.match_info["id"])
    if attempt is None:
        return _html_error("This sign-in is no longer valid. Please start again.", 404)

    script_nonce = secrets.token_urlsafe(16)
    body = render_login_page(
        attempt.client.name, attempt.id, provider.config.issuer, script_nonce, provider.config.wallet_urls
    )
    return web.Response(
        text=body,
        content_type="text/html",
        headers={**_PAGE_HEADERS, "Content-Security-Policy": csp(script_nonce)},
    )


async def login_status(request: web.Request) -> web.Response:
    """GET /oidc/login/{id}/status - polled by the browser; needs the fragment secret."""
    provider = _provider(request)
    attempt = provider.get_attempt(request.match_info["id"])
    if attempt is None or not provider.check_secret(attempt, request.headers.get("X-Login-Secret")):
        return _json({"error": "not_found"}, 404)
    return _json(provider.status(attempt))


async def login_challenge(request: web.Request) -> web.Response:
    """GET /oidc/login/{id}/challenge - what the Nodetide app signs."""
    provider = _provider(request)
    attempt = provider.get_attempt(request.match_info["id"])
    if attempt is None:
        return _json({"error": "not_found"}, 404)
    if attempt.status not in ("waiting", "fetching"):
        return _json({"error": "gone", "message": attempt.message}, 410)

    base = f"{provider.config.issuer}/oidc/login/{attempt.id}"
    return _json({
        "request": provider.current_request(attempt).to_dict(),
        "display": {
            "client_name": attempt.client.name,
            "issuer": provider.config.issuer,
            "login_hint": attempt.login_hint,
            # claims this application asked for and which attestations are acceptable
            "claims_requested": provider.claims_requested(attempt),
        },
        "respond_url": f"{base}/assertion",
    })


async def login_assertion(request: web.Request) -> web.Response:
    """POST /oidc/login/{id}/assertion - the app submits its signed AuthAssertion.

    Body: {"assertion": {...}, "sigchain": [...]?, "hints": ["https://node"]?,
           "presentations": [{"document": {...}, "attestation": {...}, "issuer_sigchain": [...]?}]?}

    Presentations are the claims the user chooses to reveal for this sign-in
    (see display.claims_requested in the challenge); at most five.
    """
    provider = _provider(request)
    attempt = provider.get_attempt(request.match_info["id"])
    if attempt is None:
        return _json({"error": "not_found"}, 404)

    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return _json({"error": "invalid_request", "message": "Invalid JSON"}, 400)
    if not isinstance(data, dict):
        return _json({"error": "invalid_request", "message": "Body must be an object"}, 400)

    hints = data.get("hints") or []
    if not isinstance(hints, list):
        return _json({"error": "invalid_request", "message": "hints must be a list"}, 400)

    result = await provider.submit_assertion(
        attempt, data.get("assertion"), data.get("sigchain"), hints[:8], data.get("presentations")
    )
    body: dict[str, Any] = {"status": result.outcome, "message": result.message}
    if result.claims is not None:
        body["claims"] = result.claims
    if result.outcome == "reapprove":
        body["challenge_url"] = f"{provider.config.issuer}/oidc/login/{attempt.id}/challenge"
    return _json(body, result.http_status)


def _client_credentials(request: web.Request, form: Any) -> tuple[str | None, str | None]:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        except Exception:
            return None, None
        client_id, _, secret = decoded.partition(":")
        return unquote_plus(client_id), unquote_plus(secret)
    cid, secret = form.get("client_id"), form.get("client_secret")
    return (cid if isinstance(cid, str) else None, secret if isinstance(secret, str) else None)


def _token_error(error: str, description: str, status: int = 400,
                 headers: dict[str, str] | None = None) -> web.Response:
    return _json({"error": error, "error_description": description}, status, headers)


async def token(request: web.Request) -> web.Response:
    """POST /oidc/token - authorization_code grant."""
    provider = _provider(request)
    form = await request.post()

    client_id, secret = _client_credentials(request, form)
    client = provider.config.clients.get(client_id or "")
    if client is None or not client.check_secret(secret):
        return _token_error(
            "invalid_client", "Client authentication failed", 401,
            {"WWW-Authenticate": 'Basic realm="nodetide"'},
        )

    if form.get("grant_type") != "authorization_code":
        return _token_error("unsupported_grant_type", "Only authorization_code is supported")

    def field(name: str) -> str | None:
        value = form.get(name)
        return value if isinstance(value, str) else None

    try:
        tokens = provider.exchange_code(
            client, field("code"), field("redirect_uri"), field("code_verifier")
        )
    except TokenError as e:
        return _token_error(e.error, e.description, e.status)
    return _json(tokens)


async def userinfo(request: web.Request) -> web.Response:
    """GET|POST /oidc/userinfo"""
    provider = _provider(request)
    header = request.headers.get("Authorization", "")
    bearer = header[7:] if header.lower().startswith("bearer ") else None
    info = provider.userinfo(bearer)
    if info is None:
        return _json({"error": "invalid_token"}, 401, {"WWW-Authenticate": 'Bearer error="invalid_token"'})
    return _json(info)


def default_claim_rules(app: web.Application, config: OIDCConfig) -> dict[str, ClaimRule]:
    """Rules derived from what the operator explicitly trusts. This node attests nothing about anyone
    and trusts no issuer unless it is named: verifying your own claims proves nothing.

    email:      attested by an email issuer or a trusted issuer
    phone:      attested by a phone issuer or a trusted issuer
    legal_name, birthdate, age_over_18:
                attested by an eID notary or a trusted issuer, always at "high" assurance (legal_name also by
                eIDAS qualified-signature proofs, if this node verifies them itself: that shows it the certificate)
    """
    trusted = frozenset(config.trusted_issuers)
    rules: dict[str, ClaimRule] = {}
    email_issuers = trusted | frozenset(config.email_issuers)
    if email_issuers:
        rules["email"] = ClaimRule("email", issuers=email_issuers)
    phone_issuers = trusted | frozenset(config.phone_issuers)
    if phone_issuers:
        rules["phone"] = ClaimRule("phone", issuers=phone_issuers)
    has_eidas = app.get("eidas_policy") is not None
    notaries = trusted | frozenset(config.notary_issuers)
    if notaries or has_eidas:
        rules["legal_name"] = ClaimRule(
            "legal_name", issuers=notaries, allow_proof=has_eidas,
            min_assurance="high", name_leniency=config.name_match,
        )
    if notaries:
        for claim_type in ("birthdate", "age_over_18"):
            rules[claim_type] = ClaimRule(claim_type, issuers=notaries, min_assurance="high")
    return rules


def setup_oidc(
    app: web.Application,
    config: OIDCConfig,
    storage: Storage,
    fetch: FetchFn | None = None,
) -> OIDCProvider:
    """Create the provider, register routes and lifecycle hooks."""
    provider = OIDCProvider(config, storage, fetch=fetch)
    provider.claim_rules = {**default_claim_rules(app, config), **config.claim_rules}

    def rules_with(issuer: str) -> dict[str, ClaimRule]:
        added = dataclasses.replace(
            config,
            email_issuers=[*config.email_issuers, issuer],
            phone_issuers=[*config.phone_issuers, issuer],
            notary_issuers=[*config.notary_issuers, issuer],
        )
        return {**default_claim_rules(app, added), **config.claim_rules}

    provider.rules_factory = rules_with
    provider.refresh_rules()
    app["oidc"] = provider

    app.router.add_get("/.well-known/openid-configuration", discovery)
    app.router.add_get("/oidc/jwks.json", jwks)
    app.router.add_get("/oidc/authorize", authorize)
    app.router.add_get("/oidc/login/{id}", login_page)
    app.router.add_get("/oidc/login/{id}/status", login_status)
    app.router.add_get("/oidc/login/{id}/challenge", login_challenge)
    app.router.add_post("/oidc/login/{id}/assertion", login_assertion)
    app.router.add_post("/oidc/token", token)
    app.router.add_get("/oidc/userinfo", userinfo)
    app.router.add_post("/oidc/userinfo", userinfo)

    async def _start(_: web.Application) -> None:
        await provider.start()

    async def _stop(_: web.Application) -> None:
        await provider.stop()

    app.on_startup.append(_start)
    app.on_cleanup.append(_stop)
    return provider
