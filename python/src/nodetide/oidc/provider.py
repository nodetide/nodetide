"""OIDC bridge state machine: sign-in attempts, authorization codes, tokens.

A relying party sends the user's browser to /oidc/authorize. The bridge opens a
*sign-in attempt* holding a Nodetide AuthRequest (audience = issuer). The user's
Nodetide app answers it with a signed AuthAssertion; the bridge verifies it
against the identity's sigchain and, if good, hands the browser back to the
relying party with an authorization code.

Unknown or stale identities are not an error to retry by hand: the attempt moves
to "fetching", the identity is queued with the IdentityFetcher, and the page
tells the user sign-in has failed *for now*.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import secrets
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from nodetide.core.auth import (
    CLOCK_SKEW,
    AuthRequest,
    AuthResult,
    choose_sigchain,
    verify_assertion,
)
from nodetide.core.claims import Attestation, ClaimDocument, ClaimError
from nodetide.core.identity import Sigchain, SigchainEvent
from nodetide.core.relying_party import ASSURANCE_RANK, ClaimRule, VerifiedClaim, evaluate_claim
from nodetide.core.storage import Storage
from nodetide.oidc.config import OIDCClient, OIDCConfig
from nodetide.oidc.fetcher import IDENTITY_RE, FetchFn, IdentityFetcher
from nodetide.oidc.keys import OIDCSigningKey

MAX_ATTEMPTS = 5000
MAX_PRESENTATIONS = 5
EIDAS_METHODS = frozenset({"eidas_qes", "eidas_notary"})  # backed by an eIDAS qualified signature

# Which claim types each scope asks for. Nothing else is ever released.
SCOPE_CLAIMS = {
    "profile": ("legal_name",), "email": ("email",), "phone": ("phone",),
    "birthdate": ("birthdate",), "age_over_18": ("age_over_18",),  # separate scopes: the person may share one without the other
}
MAX_FAILURES = 5
REQUEST_LIFETIME = 300  # one AuthRequest; rotated while the attempt lives

# User-facing messages
MSG_WAITING = "Waiting for you to approve this sign-in in your Nodetide app."
MSG_FETCHING = (
    "Nodetide doesn't know this identity yet. We've asked the network for it — "
    "this can take a few minutes. Keep this page open, or try again later."
)
MSG_STALE = (
    "We have an out-of-date copy of this identity. We're fetching the latest — "
    "this can take a few minutes. Keep this page open, or try again later."
)
MSG_FETCH_RETRY = (
    "Sign-in failed for now: we couldn't reach this identity yet. "
    "We'll keep trying in the background, so try again in a few minutes."
)
MSG_REAPPROVE = "We now know this identity. Please approve the sign-in in your app again."
MSG_APPROVED = "Approved. Returning you to the application…"
MSG_EXPIRED = "This sign-in timed out. Please start again."
MSG_EXPIRED_FETCHING = (
    "Sign-in failed for now: this identity isn't available yet. "
    "We're still fetching it in the background — try again in a few minutes."
)
MSG_TOO_MANY_FAILURES = "Too many rejected approvals. Please start again."

logger = logging.getLogger(__name__)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def add_query(uri: str, params: dict[str, str | None]) -> str:
    """Append query parameters to a redirect URI, keeping any it already has."""
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query += [(k, v) for k, v in params.items() if v is not None]
    return urlunsplit(parts._replace(query=urlencode(query)))


@dataclass
class LoginAttempt:
    id: str  # public: appears in QR codes / deep links
    secret: str  # private: lets the originating browser poll status
    client: OIDCClient
    redirect_uri: str
    state: str | None
    oidc_nonce: str | None
    scope: str
    code_challenge: str | None
    login_hint: str | None
    hint_urls: list[str]
    auth_request: AuthRequest
    created_at: int
    expires_at: int
    status: str = "waiting"  # waiting | fetching | approved | failed | expired
    message: str = MSG_WAITING
    assertion: dict[str, Any] | None = None  # held while the identity is fetched
    identity: str | None = None
    failures: int = 0
    redirect_to: str | None = None
    presentations: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AuthCode:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str | None
    oidc_nonce: str | None
    scope: str
    identity: str
    device: str
    claims: dict[str, Any]  # OIDC claims released to this client (verified, scope-limited)
    auth_time: int
    expires_at: int


@dataclass
class AccessToken:
    token: str
    identity: str
    scope: str
    claims: dict[str, Any]
    expires_at: int


@dataclass
class Submission:
    """Result of an app submitting an assertion."""

    outcome: str  # approved | fetching | reapprove | <verification error code> | ...
    http_status: int
    message: str
    claims: dict[str, Any] | None = None  # what was released / rejected (never values)


class TokenError(Exception):
    """OAuth token endpoint error (RFC 6749 section 5.2)."""

    def __init__(self, error: str, description: str, status: int = 400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


def safe_equal(a: str, b: str) -> bool:
    """Constant-time string comparison that tolerates non-ASCII input."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class OIDCProvider:
    def __init__(
        self,
        config: OIDCConfig,
        storage: Storage,
        key: OIDCSigningKey | None = None,
        fetch: FetchFn | None = None,
        clock=time.time,
    ):
        self.config = config
        self.storage = storage
        self.key = key or OIDCSigningKey.load_or_create(config.key_file)
        self._clock = clock
        self.attempts: dict[str, LoginAttempt] = {}
        self.codes: dict[str, AuthCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.claim_rules: dict[str, ClaimRule] = dict(config.claim_rules)
        self.rules_factory: Callable[[str], dict[str, ClaimRule]] | None = None  # issuer hash from the issuers file -> rules
        self._issuers_seen: tuple[int, int] | None = None  # (mtime_ns, size) of the issuers file last applied
        self.fetcher = IdentityFetcher(
            storage,
            seed_nodes=config.seed_nodes,
            fetch=fetch,
            on_update=self.on_identity_update,
            allow_private=config.allow_private_fetch,
            clock=clock,
        )

    def _now(self) -> int:
        return int(self._clock())

    # --- discovery ---------------------------------------------------------

    def discovery_document(self) -> dict[str, Any]:
        iss = self.config.issuer
        return {
            "issuer": iss,
            "authorization_endpoint": f"{iss}/oidc/authorize",
            "token_endpoint": f"{iss}/oidc/token",
            "userinfo_endpoint": f"{iss}/oidc/userinfo",
            "jwks_uri": f"{iss}/oidc/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email", "phone", "birthdate", "age_over_18"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic", "client_secret_post", "none",
            ],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "given_name",
                "family_name", "name_verified", "email", "email_verified", "phone_number",
                "phone_number_verified", "birthdate", "age_over_18", "verified_claims",
            ],
            "claims_in_verified_claims_supported": ["given_name", "family_name", "birthdate", "age_over_18"],
            "trust_frameworks_supported": ["eidas", "nodetide"],
        }

    # --- attempts ----------------------------------------------------------

    def parse_login_hint(self, login_hint: str | None) -> tuple[str | None, list[str]]:
        """login_hint is "<identity hash>" optionally followed by "@<node url>"."""
        if not login_hint:
            return None, []
        identity, _, url = login_hint.partition("@")
        identity = identity.strip().lower()
        if not IDENTITY_RE.match(identity):
            return None, []
        return identity, [url] if url else []

    def create_attempt(
        self,
        client: OIDCClient,
        redirect_uri: str,
        state: str | None,
        oidc_nonce: str | None,
        scope: str,
        code_challenge: str | None,
        login_hint: str | None,
    ) -> LoginAttempt | None:
        self.cleanup()
        if len(self.attempts) >= MAX_ATTEMPTS:
            return None
        now = self._now()
        hinted_identity, hint_urls = self.parse_login_hint(login_hint)
        attempt = LoginAttempt(
            id=secrets.token_urlsafe(16),
            secret=secrets.token_urlsafe(24),
            client=client,
            redirect_uri=redirect_uri,
            state=state,
            oidc_nonce=oidc_nonce,
            scope=scope,
            code_challenge=code_challenge,
            login_hint=hinted_identity,
            hint_urls=hint_urls,
            auth_request=AuthRequest.new(aud=self.config.issuer, lifetime=REQUEST_LIFETIME),
            created_at=now,
            expires_at=now + self.config.attempt_lifetime,
        )
        self.attempts[attempt.id] = attempt

        # Warm the cache: if the user told us who they are and we don't know
        # them, start fetching before they even approve.
        if hinted_identity and self.storage.get_sigchain(hinted_identity) is None:
            self.fetcher.schedule(hinted_identity, hint_urls)
        return attempt

    def get_attempt(self, attempt_id: str) -> LoginAttempt | None:
        attempt = self.attempts.get(attempt_id)
        if attempt is not None:
            self._refresh(attempt)
        return attempt

    def check_secret(self, attempt: LoginAttempt, secret: str | None) -> bool:
        return bool(secret) and safe_equal(attempt.secret, secret or "")

    def _refresh(self, attempt: LoginAttempt) -> None:
        if attempt.status in ("approved", "failed", "expired"):
            return
        if self._now() > attempt.expires_at:
            attempt.message = MSG_EXPIRED_FETCHING if attempt.status == "fetching" else MSG_EXPIRED
            attempt.status = "expired"
            attempt.assertion = None

    def current_request(self, attempt: LoginAttempt) -> AuthRequest:
        """The attempt's live AuthRequest, rotating it when it has expired."""
        if attempt.auth_request.is_expired and attempt.status in ("waiting", "fetching"):
            attempt.auth_request = AuthRequest.new(
                aud=self.config.issuer, lifetime=REQUEST_LIFETIME
            )
        return attempt.auth_request

    def error_redirect(self, attempt: LoginAttempt, error: str, description: str) -> str:
        return add_query(
            attempt.redirect_uri,
            {"error": error, "error_description": description, "state": attempt.state},
        )

    def status(self, attempt: LoginAttempt) -> dict[str, Any]:
        """JSON for the polling page."""
        self._refresh(attempt)
        body: dict[str, Any] = {"status": attempt.status, "message": attempt.message}

        if attempt.status == "fetching" and attempt.assertion is not None:
            info = self.fetcher.status(str(attempt.assertion.get("identity")))
            if info is not None:
                body["fetch"] = {
                    "state": info["state"],
                    "attempts": info["attempts"],
                    "next_attempt_at": info["next_attempt_at"],
                }
                if info["attempts"] > 0 and info["last_error"]:
                    body["message"] = MSG_FETCH_RETRY
        if attempt.status == "approved":
            body["redirect_to"] = attempt.redirect_to
        elif attempt.status in ("expired", "failed"):
            code = "temporarily_unavailable" if "for now" in body["message"] else "access_denied"
            body["redirect_to"] = self.error_redirect(attempt, code, body["message"])
        else:
            body["cancel_url"] = self.error_redirect(
                attempt, "access_denied", "The user cancelled the sign-in."
            )
        return body

    # --- claims ----------------------------------------------------------------

    @staticmethod
    def requested_claim_types(scope: str) -> list[str]:
        wanted: list[str] = []
        for name in scope.split():
            for claim_type in SCOPE_CLAIMS.get(name, ()):
                if claim_type not in wanted:
                    wanted.append(claim_type)
        return wanted

    def refresh_rules(self) -> None:
        """Apply the issuer the verification service has published (config.issuers_file), without a restart.

        The file is written by the verification service itself once its organization is founded; this node
        trusts exactly that one hash, for the claim types the operator allows (see default_claim_rules).
        """
        path = self.config.issuers_file
        if not path or self.rules_factory is None:
            return
        try:
            st = os.stat(path)
            if (st.st_mtime_ns, st.st_size) == self._issuers_seen:
                return
            issuer = open(path, encoding="utf-8").read().strip().lower()
        except OSError:
            return
        self._issuers_seen = (st.st_mtime_ns, st.st_size)
        if re.fullmatch(r"[0-9a-f]{64}", issuer):
            self.claim_rules = self.rules_factory(issuer)
            logger.info("trusting issuer %s from %s", issuer, path)

    def claims_requested(self, attempt: LoginAttempt) -> list[dict[str, Any]]:
        """What the user's app may present for this sign-in (rules only, no secrets)."""
        self.refresh_rules()
        return [
            self.claim_rules[t].describe()
            for t in self.requested_claim_types(attempt.scope) if t in self.claim_rules
        ]

    async def _release_claims(
        self, attempt: LoginAttempt, chain: Sigchain
    ) -> tuple[dict[str, VerifiedClaim], dict[str, Any]]:
        """Evaluate the presented claims against this bridge's rules.

        Only claim types the application asked for (via scope) are considered; an
        unsuitable presentation never fails the sign-in, it just releases nothing.
        """
        self.refresh_rules()
        wanted = set(self.requested_claim_types(attempt.scope))
        verified: dict[str, VerifiedClaim] = {}
        report: dict[str, Any] = {"released": [], "rejected": [], "ignored": 0}
        loop = asyncio.get_running_loop()

        for item in attempt.presentations:
            try:
                document = ClaimDocument.from_dict(item.get("document"))
                attestation = Attestation.from_dict(item.get("attestation"))
            except (ClaimError, AttributeError):
                report["rejected"].append({"claim_type": None, "code": "invalid_presentation"})
                continue
            # A light presenter sends the control chain only, and for each claim the event with its Merkle path
            if isinstance(item.get("claim_event"), dict):
                try:
                    problem = chain.attach_content(SigchainEvent.from_dict(item["claim_event"]), item.get("claim_proof") or [])
                except Exception:
                    problem = "malformed claim event"
                if problem:
                    code = "behind" if problem.startswith("behind:") else "bad_claim_proof"
                    report["rejected"].append({"claim_type": attestation.claim_type, "code": code, "detail": problem})
                    continue
            claim_type = attestation.claim_type
            rule = self.claim_rules.get(claim_type)
            if claim_type not in wanted or rule is None:
                report["ignored"] += 1
                continue
            if attestation.subject != chain.identity_hash:
                report["rejected"].append({"claim_type": claim_type, "code": "wrong_identity"})
                continue

            issuer_chain = None
            if attestation.issuer is not None:
                supplied = item.get("issuer_sigchain")
                provided = None
                if isinstance(supplied, list):
                    try:
                        provided = Sigchain.from_list(supplied)
                    except Exception:
                        provided = None
                issuer_chain, _ = choose_sigchain(self.storage.get_sigchain(attestation.issuer), provided)
            revoked = self.storage.get_attestation_revocation(attestation.id) is not None

            outcome = await loop.run_in_executor(None, lambda: evaluate_claim(
                rule, document, attestation, chain, issuer_chain, revoked=revoked, now=self._now(),
                resolve=self.storage.get_sigchain))
            if outcome.claim is None:
                report["rejected"].append({"claim_type": claim_type, "code": outcome.code})
                continue
            best = verified.get(claim_type)
            if best is None or ASSURANCE_RANK[outcome.claim.assurance] > ASSURANCE_RANK[best.assurance]:
                verified[claim_type] = outcome.claim

        report["released"] = [
            {"claim_type": c.claim_type, "assurance": c.assurance, "method": c.method} for c in verified.values()
        ]
        return verified, report

    @staticmethod
    def oidc_claims(
        verified: dict[str, VerifiedClaim], scope: str, display_name: str | None
    ) -> dict[str, Any]:
        """Map verified claims to standard OIDC claims, limited to what the scope asked for."""
        scopes = set(scope.split())
        claims: dict[str, Any] = {}
        if "profile" in scopes:
            legal = verified.get("legal_name")
            if legal is not None:
                given, family = legal.value["given_name"], legal.value["family_name"]
                claims.update(given_name=given, family_name=family, name=f"{given} {family}", name_verified=True)
                claims["verified_claims"] = [{
                    "verification": {
                        "trust_framework": "eidas" if legal.method in EIDAS_METHODS else "nodetide",
                        "assurance_level": legal.assurance,
                        "time": datetime.fromtimestamp(legal.issued_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                    "claims": {"given_name": given, "family_name": family},
                }]
            elif display_name:
                # the name in the identity's genesis event: self-asserted, so say so
                claims.update(name=display_name, name_verified=False)
        for claim_type in ("birthdate", "age_over_18"):
            if claim_type in scopes and claim_type in verified:
                item = verified[claim_type]
                claims[claim_type] = item.value
                claims.setdefault("verified_claims", []).append({
                    "verification": {
                        "trust_framework": "eidas" if item.method in EIDAS_METHODS else "nodetide",
                        "assurance_level": item.assurance,
                        "time": datetime.fromtimestamp(item.issued_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                    "claims": {claim_type: item.value},
                })
        if "email" in scopes and "email" in verified:
            claims.update(email=verified["email"].value, email_verified=True)
        if "phone" in scopes and "phone" in verified:
            claims.update(phone_number=verified["phone"].value, phone_number_verified=True)
        return claims

    # --- assertions --------------------------------------------------------

    async def submit_assertion(
        self,
        attempt: LoginAttempt,
        assertion: Any,
        supplied_chain: Any = None,
        hints: Iterable[str] = (),
        presentations: Any = None,
    ) -> Submission:
        self._refresh(attempt)
        if attempt.status == "approved":
            return Submission("conflict", 409, "This sign-in was already completed.")
        if attempt.status in ("expired", "failed"):
            return Submission("gone", 410, attempt.message)

        if not isinstance(assertion, dict):
            return Submission("invalid_request", 400, "Missing assertion")
        nonce, identity = assertion.get("nonce"), assertion.get("identity")
        if not isinstance(nonce, str) or not isinstance(identity, str):
            return Submission("invalid_request", 400, "Assertion needs string nonce and identity")
        if not IDENTITY_RE.match(identity):
            return Submission("invalid_request", 400, "Invalid identity")
        if not safe_equal(nonce, self.current_request(attempt).nonce):
            return Submission("unknown_challenge", 401, "Challenge expired; fetch a fresh one.")

        provided: Sigchain | None = None
        if supplied_chain is not None:
            if not isinstance(supplied_chain, list):
                return Submission("invalid_request", 400, "sigchain must be a list of events")
            try:
                provided = Sigchain.from_list(supplied_chain)
            except Exception:
                return Submission("invalid_request", 400, "Malformed sigchain")

        chain, conflict = choose_sigchain(self.storage.get_sigchain(identity), provided)
        if conflict:
            return Submission("conflict", 409, "Supplied sigchain conflicts with the stored one.")

        if presentations is not None:
            if not isinstance(presentations, list) or len(presentations) > MAX_PRESENTATIONS \
                    or not all(isinstance(p, dict) for p in presentations):
                return Submission("invalid_request", 400, f"presentations must be a list of at most {MAX_PRESENTATIONS} objects")
            attempt.presentations = presentations

        hint_list = list(attempt.hint_urls) + [h for h in hints if isinstance(h, str)]
        if chain is None:
            return self._start_fetch(attempt, assertion, hint_list, MSG_FETCHING)
        return await self._evaluate(attempt, assertion, chain, hint_list)

    def _start_fetch(
        self,
        attempt: LoginAttempt,
        assertion: dict[str, Any],
        hints: list[str],
        message: str,
    ) -> Submission:
        identity = assertion["identity"]
        want_head = assertion.get("chain_head")
        if not self.fetcher.schedule(identity, hints, want_head if isinstance(want_head, str) else None):
            return Submission(
                "fetch_unavailable", 503,
                "Sign-in failed for now: the node can't look up new identities right now. "
                "Try again in a few minutes.",
            )
        attempt.assertion = assertion
        attempt.status = "fetching"
        attempt.message = message
        return Submission("fetching", 202, message)

    async def _evaluate(
        self,
        attempt: LoginAttempt,
        assertion: dict[str, Any],
        chain: Sigchain,
        hints: list[str],
        after_fetch: bool = False,
    ) -> Submission:
        request = attempt.auth_request
        result = verify_assertion(assertion, chain, expected_aud=self.config.issuer, now=self._now())
        if result.ok and assertion["exp"] > request.expires_at + CLOCK_SKEW:
            result = AuthResult.fail("invalid_assertion", "Assertion outlives its challenge")

        if result.ok:
            return await self._approve(attempt, result, chain)

        if result.code == "unknown_chain_head":
            return self._start_fetch(attempt, assertion, hints, MSG_STALE)

        attempt.assertion = None
        if after_fetch and result.code == "expired":
            # The identity is known now, but the old approval timed out while we
            # were fetching. Ask the user to approve again (instant this time).
            attempt.status = "waiting"
            attempt.auth_request = AuthRequest.new(aud=self.config.issuer, lifetime=REQUEST_LIFETIME)
            attempt.message = MSG_REAPPROVE
            return Submission("reapprove", 202, MSG_REAPPROVE)

        attempt.failures += 1
        attempt.message = f"Approval rejected: {result.error}"
        if attempt.failures >= MAX_FAILURES:
            attempt.status = "failed"
            attempt.message = MSG_TOO_MANY_FAILURES
        else:
            attempt.status = "waiting"
        return Submission(result.code or "invalid_assertion", 401, attempt.message)

    async def _approve(self, attempt: LoginAttempt, result: AuthResult, chain: Sigchain) -> Submission:
        now = self._now()
        genesis = chain.genesis
        verified, report = await self._release_claims(attempt, chain)
        claims = self.oidc_claims(verified, attempt.scope, genesis.name if genesis is not None else None)
        attempt.presentations = []
        code = secrets.token_urlsafe(32)
        self.codes[code] = AuthCode(
            code=code,
            client_id=attempt.client.client_id,
            redirect_uri=attempt.redirect_uri,
            code_challenge=attempt.code_challenge,
            oidc_nonce=attempt.oidc_nonce,
            scope=attempt.scope,
            identity=result.identity or "",
            device=result.device or "",
            claims=claims,
            auth_time=now,
            expires_at=now + self.config.code_lifetime,
        )
        attempt.status = "approved"
        attempt.identity = result.identity
        attempt.assertion = None
        attempt.message = MSG_APPROVED
        attempt.redirect_to = add_query(attempt.redirect_uri, {"code": code, "state": attempt.state})
        return Submission("approved", 200, MSG_APPROVED, claims=report)

    async def on_identity_update(self, identity_hash: str) -> None:
        """Called by the fetcher when a chain was stored: finish waiting attempts."""
        chain = self.storage.get_sigchain(identity_hash)
        if chain is None:
            return
        for attempt in list(self.attempts.values()):
            self._refresh(attempt)
            if (
                attempt.status == "fetching"
                and attempt.assertion is not None
                and attempt.assertion.get("identity") == identity_hash
            ):
                await self._evaluate(attempt, attempt.assertion, chain, [], after_fetch=True)

    # --- token endpoint ----------------------------------------------------

    def exchange_code(
        self,
        client: OIDCClient,
        code: str | None,
        redirect_uri: str | None,
        code_verifier: str | None,
    ) -> dict[str, Any]:
        # Codes are single use: remove first so failed guesses cannot be retried.
        auth_code = self.codes.pop(code, None) if code else None
        if auth_code is None or self._now() > auth_code.expires_at:
            raise TokenError("invalid_grant", "Unknown, used or expired code")
        if auth_code.client_id != client.client_id:
            raise TokenError("invalid_grant", "Code was issued to another client")
        if auth_code.redirect_uri != redirect_uri:
            raise TokenError("invalid_grant", "redirect_uri mismatch")

        if auth_code.code_challenge:
            if not code_verifier or not (43 <= len(code_verifier) <= 128):
                raise TokenError("invalid_grant", "code_verifier required")
            expected = b64url(hashlib.sha256(code_verifier.encode("ascii", "ignore")).digest())
            if not safe_equal(expected, auth_code.code_challenge):
                raise TokenError("invalid_grant", "PKCE verification failed")
        elif client.is_public:
            raise TokenError("invalid_grant", "PKCE required for public clients")

        now = self._now()
        claims: dict[str, Any] = {
            "iss": self.config.issuer,
            "sub": auth_code.identity,
            "aud": client.client_id,
            "iat": now,
            "exp": now + self.config.id_token_lifetime,
            "auth_time": auth_code.auth_time,
            "nodetide_device": auth_code.device,
        }
        if auth_code.oidc_nonce:
            claims["nonce"] = auth_code.oidc_nonce
        # Released claims first, so they can never override the registered ones above.
        claims = {**auth_code.claims, **claims}

        access_token = "at_" + secrets.token_urlsafe(32)
        self.access_tokens[access_token] = AccessToken(
            token=access_token,
            identity=auth_code.identity,
            scope=auth_code.scope,
            claims=auth_code.claims,
            expires_at=now + self.config.access_token_lifetime,
        )
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.access_token_lifetime,
            "id_token": self.key.sign_jwt(claims),
        }

    def userinfo(self, token: str | None) -> dict[str, Any] | None:
        access = self.access_tokens.get(token) if token else None
        if access is None or self._now() > access.expires_at:
            return None
        return {**access.claims, "sub": access.identity}

    # --- housekeeping ------------------------------------------------------

    def cleanup(self) -> None:
        now = self._now()
        for attempt_id, attempt in list(self.attempts.items()):
            # keep finished attempts around briefly so the page can read the result
            if now > attempt.expires_at + 300:
                del self.attempts[attempt_id]
        for code, auth_code in list(self.codes.items()):
            if now > auth_code.expires_at:
                del self.codes[code]
        for token, access in list(self.access_tokens.items()):
            if now > access.expires_at:
                del self.access_tokens[token]

    async def start(self) -> None:
        await self.fetcher.start()

    async def stop(self) -> None:
        await self.fetcher.stop()
