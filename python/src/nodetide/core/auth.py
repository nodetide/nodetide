"""Native authentication (SSO) - challenge/response with sigchain-backed keys.

See "Authentication (SSO)" in identity-system.md.

An AuthRequest is issued by a relying party (RP). A device key holding the
`authenticate` capability signs an AuthAssertion bound to the RP's origin and
nonce. The RP verifies the assertion against the identity's sigchain.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from nodetide.core.crypto import KeyPair, SigningKey, VerifyKey
from nodetide.core.identity import DeviceCapability, Sigchain

# Domain separation: prepended to every signed assertion so the signature can
# never be valid as an event, message, file or trust-assertion signature.
AUTH_DOMAIN = b"nodetide-auth-v1\x00"

AUTH_REQUEST_TYPE = "AUTH_REQUEST"
AUTH_ASSERTION_TYPE = "AUTH_ASSERTION"

# Limits
MAX_REQUEST_LIFETIME = 600  # seconds an AuthRequest may stay valid
DEFAULT_REQUEST_LIFETIME = 300
MAX_ASSERTION_LIFETIME = 600  # exp - iat
CLOCK_SKEW = 60  # seconds


def canonical_json(obj: Any) -> bytes:
    """Canonical JSON used for signing (matches the rest of the codebase)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signing_input(assertion: dict[str, Any]) -> bytes:
    """Bytes that are signed for an assertion dict (everything except `sig`)."""
    body = {k: v for k, v in assertion.items() if k != "sig"}
    return AUTH_DOMAIN + canonical_json(body)


@dataclass
class AuthRequest:
    """Challenge issued by a relying party."""

    aud: str
    nonce: str
    issued_at: int
    expires_at: int
    callback: str | None = None
    claims: list[str] = field(default_factory=list)
    type: str = AUTH_REQUEST_TYPE

    @classmethod
    def new(
        cls,
        aud: str,
        lifetime: int = DEFAULT_REQUEST_LIFETIME,
        callback: str | None = None,
        claims: list[str] | None = None,
    ) -> AuthRequest:
        now = int(time.time())
        lifetime = max(1, min(int(lifetime), MAX_REQUEST_LIFETIME))
        return cls(
            aud=aud,
            nonce=secrets.token_urlsafe(24),  # 192 bits
            issued_at=now,
            expires_at=now + lifetime,
            callback=callback,
            claims=claims or [],
        )

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": self.type,
            "aud": self.aud,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        if self.callback:
            d["callback"] = self.callback
        if self.claims:
            d["claims"] = self.claims
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthRequest:
        if data.get("type") != AUTH_REQUEST_TYPE:
            raise ValueError("Not an AUTH_REQUEST")
        return cls(
            aud=data["aud"],
            nonce=data["nonce"],
            issued_at=int(data["issued_at"]),
            expires_at=int(data["expires_at"]),
            callback=data.get("callback"),
            claims=list(data.get("claims") or []),
        )


def create_assertion(
    request: AuthRequest | dict[str, Any],
    identity: str,
    device_key: SigningKey | KeyPair,
    chain_head: str,
    claims: dict[str, Any] | None = None,
    lifetime: int = DEFAULT_REQUEST_LIFETIME,
    now: int | None = None,
) -> dict[str, Any]:
    """Create and sign an AuthAssertion answering `request`.

    `device_key` must be a device key (not the master key) holding the
    `authenticate` capability in the identity's sigchain.
    """
    if isinstance(request, dict):
        request = AuthRequest.from_dict(request)
    signer = device_key.signing_key if isinstance(device_key, KeyPair) else device_key

    iat = int(time.time()) if now is None else now
    exp = min(iat + lifetime, iat + MAX_ASSERTION_LIFETIME, request.expires_at)

    assertion: dict[str, Any] = {
        "type": AUTH_ASSERTION_TYPE,
        "identity": identity,
        "device": signer.verify_key.to_hex(),
        "aud": request.aud,
        "nonce": request.nonce,
        "iat": iat,
        "exp": exp,
        "chain_head": chain_head,
    }
    if claims:
        assertion["claims"] = claims
    assertion["sig"] = signer.sign_hex(signing_input(assertion))
    return assertion


def choose_sigchain(
    stored: Sigchain | None,
    provided: Sigchain | None,
) -> tuple[Sigchain | None, str | None]:
    """Pick between a stored and a supplied copy of one identity's sigchain.

    The longer copy wins when one extends the other, so a caller cannot hide a
    revocation by supplying an older prefix. Returns (chain, None); (None, None)
    when neither exists (identity unknown); or (None, "conflict") when the two
    diverge (a fork).
    """
    if provided is None:
        return stored, None
    if stored is None:
        return provided, None

    def longer(a: list, b: list) -> list | None:
        """The one of two hash lists that extends the other, or None when they diverge."""
        n = min(len(a), len(b))
        if a[:n] != b[:n]:
            return None
        return a if len(a) >= len(b) else b

    control = longer([e.event_hash() for e in stored.events], [e.event_hash() for e in provided.events])
    content = longer([e.event_hash() for e in stored.content], [e.event_hash() for e in provided.content])
    if control is None or content is None:
        return None, "conflict"
    # control and content may each be longer on a different side (a light copy is newer in control but has no content)
    best_control = provided.events if len(provided.events) > len(stored.events) else stored.events
    best_content = provided.content if len(provided.content) > len(stored.content) else stored.content
    if best_control is stored.events and best_content is stored.content:
        return stored, None
    if best_control is provided.events and best_content is provided.content:
        return provided, None
    merged = Sigchain(events=list(best_control), content=list(best_content))
    return merged, None


@dataclass
class AuthResult:
    """Outcome of verifying an assertion."""

    ok: bool
    error: str | None = None
    # Machine-readable reason: invalid_assertion, wrong_audience, expired,
    # unknown_chain_head, device_not_authorized, bad_signature, ...
    code: str | None = None
    identity: str | None = None
    device: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def fail(cls, code: str, message: str) -> AuthResult:
        return cls(ok=False, error=message, code=code)


def verify_assertion(
    assertion: dict[str, Any],
    sigchain: Sigchain,
    expected_aud: str,
    now: int | None = None,
) -> AuthResult:
    """Verify an AuthAssertion against a sigchain.

    Checks (spec "RP Verification"): audience, time window, sigchain validity,
    identity match, chain_head known, device active with `authenticate`, and
    the signature. Nonce handling (single use) is the caller's job.
    """
    now = int(time.time()) if now is None else now

    if not isinstance(assertion, dict):
        return AuthResult.fail("invalid_assertion", "Assertion must be an object")
    if assertion.get("type") != AUTH_ASSERTION_TYPE:
        return AuthResult.fail("invalid_assertion", "Not an AUTH_ASSERTION")

    for name in ("identity", "device", "aud", "nonce", "chain_head", "sig"):
        if not isinstance(assertion.get(name), str) or not assertion[name]:
            return AuthResult.fail("invalid_assertion", f"Missing or invalid field: {name}")
    for name in ("iat", "exp"):
        value = assertion.get(name)
        if isinstance(value, bool) or not isinstance(value, int):
            return AuthResult.fail("invalid_assertion", f"Missing or invalid field: {name}")
    claims = assertion.get("claims", {})
    if not isinstance(claims, dict):
        return AuthResult.fail("invalid_assertion", "claims must be an object")

    # 1. Audience and time window
    if assertion["aud"] != expected_aud:
        return AuthResult.fail("wrong_audience", "Assertion audience does not match")
    iat, exp = assertion["iat"], assertion["exp"]
    if exp <= iat or exp - iat > MAX_ASSERTION_LIFETIME:
        return AuthResult.fail("invalid_assertion", "Invalid assertion lifetime")
    if iat > now + CLOCK_SKEW:
        return AuthResult.fail("expired", "Assertion issued in the future")
    if now > exp + CLOCK_SKEW:
        return AuthResult.fail("expired", "Assertion expired")

    # 2. Sigchain verifies from genesis and belongs to the claimed identity
    valid, err = sigchain.verify()
    if not valid:
        return AuthResult.fail("invalid_sigchain", err or "Invalid sigchain")
    if sigchain.identity_hash != assertion["identity"]:
        return AuthResult.fail("invalid_assertion", "Sigchain does not match identity")

    # 3. chain_head must be in the chain we hold (else our chain is stale)
    known_hashes = {e.event_hash() for e in sigchain.events}
    if assertion["chain_head"] not in known_hashes:
        return AuthResult.fail(
            "unknown_chain_head",
            "Signer knows a sigchain event we do not; fetch a newer sigchain",
        )

    # 4. Device is active, is not the master key, and holds `authenticate`
    device_hex = assertion["device"]
    if device_hex == sigchain.get_current_master_key():
        return AuthResult.fail("device_not_authorized", "Master key may not sign assertions")
    device = next((d for d in sigchain.get_active_devices(now) if d.pubkey == device_hex), None)
    if device is None:
        return AuthResult.fail("device_not_authorized", "Device is not active")
    if DeviceCapability.AUTHENTICATE.value not in device.capabilities:
        return AuthResult.fail("device_not_authorized", "Device lacks authenticate capability")
    if device.added_at > iat + CLOCK_SKEW:
        return AuthResult.fail("device_not_authorized", "Device was added after assertion")

    # 5. Signature
    try:
        key = VerifyKey.from_hex(device_hex)
        sig_ok = key.verify_hex(signing_input(assertion), assertion["sig"])
    except Exception:
        sig_ok = False
    if not sig_ok:
        return AuthResult.fail("bad_signature", "Signature verification failed")

    return AuthResult(
        ok=True,
        identity=assertion["identity"],
        device=device_hex,
        claims=claims,
    )
