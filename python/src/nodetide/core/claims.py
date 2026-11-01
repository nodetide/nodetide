"""Claims and attestations (see "Claims and Attestations" in identity-system.md).

A *claim* is something an identity says about itself. Only a salted commitment
goes on the sigchain (AddClaimEvent); the value lives in a ClaimDocument that the
holder reveals to chosen parties. An *attestation* is a signed statement by a
third party that it verified a claim. Whether to believe an attestation is the
relying party's decision.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
import secrets
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable

from nodetide.core.auth import canonical_json
from nodetide.core.crypto import KeyPair, SigningKey, VerifyKey
from nodetide.core.identity import ClaimRecord, DeviceCapability, Sigchain

CLAIM_DOMAIN = b"nodetide-claim-v1\x00"
ATTEST_DOMAIN = b"nodetide-attest-v1\x00"
ATTEST_REVOKE_DOMAIN = b"nodetide-attest-revoke-v1\x00"
PUBLISH_DOMAIN = b"nodetide-claim-publish-v1\x00"

ATTESTATION_TYPE = "ATTESTATION"
CLOCK_SKEW = 300
MAX_ATTESTATION_LIFETIME = 2 * 365 * 86400
DEFAULT_ATTESTATION_LIFETIME = 365 * 86400

ASSURANCE_LEVELS = ("low", "substantial", "high")
STANDARD_CLAIM_TYPES = ("email", "phone", "legal_name", "birthdate", "age_over_18")

_EXT_TYPE_RE = re.compile(r"^x-[a-z0-9]{1,32}:[a-z0-9_]{1,48}$")
_METHOD_RE = re.compile(r"^(x-[a-z0-9]{1,32}:)?[a-z0-9_]{1,48}$")
_CLAIM_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_PHONE_RE = re.compile(r"^\+[1-9][0-9]{6,14}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_EMAIL_LOCAL_RE = re.compile(r"^[^\s@\x00-\x1f]{1,64}$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class ClaimError(ValueError):
    """Invalid claim, claim document or attestation."""


def _contains_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, list):
        return any(_contains_float(v) for v in value)
    if isinstance(value, dict):
        return any(_contains_float(v) for v in value.values())
    return False


# --- values -------------------------------------------------------------------


def is_valid_claim_type(claim_type: Any) -> bool:
    return isinstance(claim_type, str) and (
        claim_type in STANDARD_CLAIM_TYPES or bool(_EXT_TYPE_RE.match(claim_type))
    )


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _normalize_generic(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        raise ClaimError("value is nested too deeply")
    if isinstance(value, str):
        return _nfc(value)
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, list):
        return [_normalize_generic(v, depth + 1) for v in value]
    if isinstance(value, dict):
        return {_nfc(str(k)): _normalize_generic(v, depth + 1) for k, v in value.items()}
    raise ClaimError("value contains an unsupported type")


def normalize_value(claim_type: str, value: Any) -> Any:
    """Canonical form of a claim value, so equal values give equal commitments."""
    if not is_valid_claim_type(claim_type):
        raise ClaimError(f"unknown claim type: {claim_type!r}")

    if claim_type == "email":
        if not isinstance(value, str):
            raise ClaimError("email must be a string")
        text = _nfc(value.strip())
        local, at, domain = text.rpartition("@")
        if not at or not _EMAIL_LOCAL_RE.match(local):
            raise ClaimError("invalid email address")
        try:
            ascii_domain = domain.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ClaimError("invalid email domain") from None
        labels = ascii_domain.split(".")
        if len(labels) < 2 or not all(_DOMAIN_LABEL_RE.match(lbl) for lbl in labels):
            raise ClaimError("invalid email domain")
        result = f"{local}@{ascii_domain}"
        if len(result) > 254:
            raise ClaimError("email address is too long")
        return result

    if claim_type == "phone":
        if not isinstance(value, str):
            raise ClaimError("phone must be a string")
        text = re.sub(r"[\s().-]", "", value)
        if not _PHONE_RE.match(text):
            raise ClaimError("phone must be an E.164 number such as +359881234567")
        return text

    if claim_type == "legal_name":
        if not isinstance(value, dict) or set(value) != {"given_name", "family_name"}:
            raise ClaimError('legal_name needs exactly "given_name" and "family_name"')
        result = {}
        for key in ("given_name", "family_name"):
            part = value[key]
            if not isinstance(part, str) or not part.strip() or len(part) > 100:
                raise ClaimError(f"{key} must be a non-empty string")
            result[key] = _nfc(part.strip())
        return result

    if claim_type == "birthdate":
        if not isinstance(value, str) or not _DATE_RE.match(value.strip()):
            raise ClaimError("birthdate must be a date like 1990-04-23")
        try:
            born = date.fromisoformat(value.strip())
        except ValueError:
            raise ClaimError("birthdate is not a real date") from None
        if born > date.today() or born.year < 1880:
            raise ClaimError("birthdate is out of range")
        return born.isoformat()

    if claim_type == "age_over_18":
        if value is not True:
            raise ClaimError("age_over_18 is true or it is not claimed")
        return True

    normalized = _normalize_generic(value)
    if len(canonical_json(normalized)) > 2048:
        raise ClaimError("value is too large")
    return normalized


def compute_commitment(claim_id: str, claim_type: str, salt: bytes, value: Any) -> str:
    """hex(sha256("nodetide-claim-v1\\0" || claim_id || 0 || claim_type || 0 || salt || 0 || canonical(value)))"""
    if len(salt) != 16:
        raise ClaimError("salt must be 16 bytes")
    material = (
        CLAIM_DOMAIN
        + claim_id.encode("utf-8") + b"\x00"
        + claim_type.encode("utf-8") + b"\x00"
        + salt + b"\x00"
        + canonical_json(normalize_value(claim_type, value))
    )
    return hashlib.sha256(material).hexdigest()


@dataclass
class ClaimDocument:
    """A claim with its value and salt. Kept by the holder; reveal deliberately."""

    identity: str
    claim_id: str
    claim_type: str
    value: Any
    salt: str  # 16 random bytes, hex

    def __post_init__(self) -> None:
        if not _HASH_RE.match(self.identity or ""):
            raise ClaimError("identity must be an identity hash")
        if not _CLAIM_ID_RE.match(self.claim_id or ""):
            raise ClaimError("invalid claim_id")
        if not isinstance(self.salt, str) or not re.fullmatch(r"[0-9a-f]{32}", self.salt):
            raise ClaimError("salt must be 16 bytes of hex")
        self.value = normalize_value(self.claim_type, self.value)

    @staticmethod
    def new_claim_id() -> str:
        """128 random bits, base64url, never starting with "-" (so it can be typed as a CLI argument)."""
        while True:
            candidate = secrets.token_urlsafe(16)
            if candidate[0].isalnum():
                return candidate

    @classmethod
    def create(cls, identity: str, claim_type: str, value: Any) -> ClaimDocument:
        return cls(
            identity=identity,
            claim_id=cls.new_claim_id(),
            claim_type=claim_type,
            value=value,
            salt=secrets.token_bytes(16).hex(),
        )

    @property
    def commitment(self) -> str:
        return compute_commitment(self.claim_id, self.claim_type, bytes.fromhex(self.salt), self.value)

    def matches(self, record: ClaimRecord | None) -> bool:
        """Whether this document is the one committed to by a chain record."""
        return (
            record is not None
            and record.claim_id == self.claim_id
            and record.claim_type == self.claim_type
            and secrets.compare_digest(record.commitment, self.commitment)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "value": self.value,
            "salt": self.salt,
        }

    @classmethod
    def from_dict(cls, data: Any) -> ClaimDocument:
        if not isinstance(data, dict):
            raise ClaimError("claim document must be an object")
        try:
            return cls(
                identity=data["identity"],
                claim_id=data["claim_id"],
                claim_type=data["claim_type"],
                value=data["value"],
                salt=data["salt"],
            )
        except KeyError as e:
            raise ClaimError(f"claim document is missing {e.args[0]}") from None


def publication_signing_input(action: str, document: dict[str, Any], issued_at: int) -> bytes:
    """Bytes a holder's device key signs to publish or unpublish a claim document."""
    body = {"action": action, "document": document, "issued_at": issued_at}
    return PUBLISH_DOMAIN + canonical_json(body)


# --- attestations -------------------------------------------------------------


@dataclass
class Attestation:
    """A third party's signed statement that it verified a claim."""

    subject: str
    claim_id: str
    claim_type: str
    commitment: str
    method: str
    assurance: str
    issued_at: int
    expires_at: int
    chain_head: str
    issuer: str | None = None  # absent for self-contained proofs
    signed_by: str | None = None  # issuer device key (hex)
    evidence: dict[str, Any] = field(default_factory=dict)
    proof: dict[str, Any] | None = None
    sig: str | None = None
    version: int = 1
    type: str = ATTESTATION_TYPE

    def body(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": self.type,
            "version": self.version,
            "subject": self.subject,
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "commitment": self.commitment,
            "method": self.method,
            "assurance": self.assurance,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "chain_head": self.chain_head,
            "evidence": self.evidence,
        }
        if self.issuer is not None:
            d["issuer"] = self.issuer
        if self.signed_by is not None:
            d["signed_by"] = self.signed_by
        if self.proof is not None:
            d["proof"] = self.proof
        return d

    def to_dict(self) -> dict[str, Any]:
        d = self.body()
        if self.sig is not None:
            d["sig"] = self.sig
        return d

    @property
    def id(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict())).hexdigest()

    def signing_input(self) -> bytes:
        return ATTEST_DOMAIN + canonical_json(self.body())

    @classmethod
    def from_dict(cls, data: Any) -> Attestation:
        """Parse and structurally validate (no signature or chain checks)."""
        if not isinstance(data, dict):
            raise ClaimError("attestation must be an object")
        if data.get("type") != ATTESTATION_TYPE or data.get("version") != 1:
            raise ClaimError("not a version 1 ATTESTATION")

        def text(name: str, pattern: re.Pattern | None = None, optional: bool = False) -> Any:
            value = data.get(name)
            if value is None and optional:
                return None
            if not isinstance(value, str) or not value or len(value) > 512:
                raise ClaimError(f"{name} must be a non-empty string")
            if pattern is not None and not pattern.match(value):
                raise ClaimError(f"{name} is malformed")
            return value

        def integer(name: str) -> int:
            value = data.get(name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ClaimError(f"{name} must be an integer")
            return value

        claim_type = text("claim_type")
        if not is_valid_claim_type(claim_type):
            raise ClaimError("unknown claim type")
        assurance = text("assurance")
        if assurance not in ASSURANCE_LEVELS:
            raise ClaimError("assurance must be low, substantial or high")
        evidence = data.get("evidence", {})
        proof = data.get("proof")
        if not isinstance(evidence, dict) or (proof is not None and not isinstance(proof, dict)):
            raise ClaimError("evidence and proof must be objects")
        if _contains_float(evidence) or _contains_float(proof):
            raise ClaimError("floating point numbers are not allowed in evidence or proof")
        if len(canonical_json(evidence)) > 4096:
            raise ClaimError("evidence is too large")
        if proof is not None and len(canonical_json(proof)) > 512 * 1024:
            raise ClaimError("proof is too large")

        issued_at, expires_at = integer("issued_at"), integer("expires_at")
        if expires_at <= issued_at or expires_at - issued_at > MAX_ATTESTATION_LIFETIME:
            raise ClaimError("invalid attestation lifetime")

        issuer = text("issuer", _HASH_RE, optional=True)
        sig = text("sig", re.compile(r"^[0-9a-f]{128}$"), optional=True)
        signed_by = text("signed_by", re.compile(r"^[0-9a-f]{64}$"), optional=True)
        if proof is None and (issuer is None or sig is None or signed_by is None):
            raise ClaimError("an issued attestation needs issuer, signed_by and sig")
        if proof is not None and (issuer is not None or sig is not None):
            raise ClaimError("a self-contained proof has no issuer or sig")

        return cls(
            subject=text("subject", _HASH_RE),
            claim_id=text("claim_id", _CLAIM_ID_RE),
            claim_type=claim_type,
            commitment=text("commitment", _HASH_RE),
            method=text("method", _METHOD_RE),
            assurance=assurance,
            issued_at=issued_at,
            expires_at=expires_at,
            chain_head=text("chain_head", _HASH_RE),
            issuer=issuer,
            signed_by=signed_by,
            evidence=evidence,
            proof=proof,
            sig=sig,
        )

    @classmethod
    def issue(
        cls,
        issuer: str,
        device_key: SigningKey | KeyPair,
        subject: str,
        record: ClaimRecord,
        chain_head: str,
        method: str,
        assurance: str,
        evidence: dict[str, Any] | None = None,
        lifetime: int = DEFAULT_ATTESTATION_LIFETIME,
        now: int | None = None,
    ) -> Attestation:
        """Create and sign an attestation for a claim on the subject's chain."""
        signer = device_key.signing_key if isinstance(device_key, KeyPair) else device_key
        issued_at = int(time.time()) if now is None else now
        att = cls(
            subject=subject,
            claim_id=record.claim_id,
            claim_type=record.claim_type,
            commitment=record.commitment,
            method=method,
            assurance=assurance,
            issued_at=issued_at,
            expires_at=issued_at + min(lifetime, MAX_ATTESTATION_LIFETIME),
            chain_head=chain_head,
            issuer=issuer,
            signed_by=signer.verify_key.to_hex(),
            evidence=evidence or {},
        )
        att.sig = signer.sign_hex(att.signing_input())
        return cls.from_dict(att.to_dict())  # re-validates what we produced


@dataclass
class AttestationRevocation:
    """An issuer withdrawing an attestation."""

    attestation_id: str
    issuer: str
    signed_by: str
    reason: str | None
    issued_at: int
    sig: str = ""

    def body(self) -> dict[str, Any]:
        return {
            "type": "ATTESTATION_REVOCATION",
            "attestation_id": self.attestation_id,
            "issuer": self.issuer,
            "signed_by": self.signed_by,
            "reason": self.reason,
            "issued_at": self.issued_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.sig}

    def signing_input(self) -> bytes:
        return ATTEST_REVOKE_DOMAIN + canonical_json(self.body())

    @classmethod
    def create(
        cls,
        issuer: str,
        device_key: SigningKey | KeyPair,
        attestation_id: str,
        reason: str | None = None,
        now: int | None = None,
    ) -> AttestationRevocation:
        signer = device_key.signing_key if isinstance(device_key, KeyPair) else device_key
        rev = cls(
            attestation_id=attestation_id,
            issuer=issuer,
            signed_by=signer.verify_key.to_hex(),
            reason=reason,
            issued_at=int(time.time()) if now is None else now,
        )
        rev.sig = signer.sign_hex(rev.signing_input())
        return rev

    @classmethod
    def from_dict(cls, data: Any) -> AttestationRevocation:
        if not isinstance(data, dict) or data.get("type") != "ATTESTATION_REVOCATION":
            raise ClaimError("not an ATTESTATION_REVOCATION")
        try:
            rev = cls(
                attestation_id=data["attestation_id"],
                issuer=data["issuer"],
                signed_by=data["signed_by"],
                reason=data.get("reason"),
                issued_at=data["issued_at"],
                sig=data["sig"],
            )
        except KeyError as e:
            raise ClaimError(f"revocation is missing {e.args[0]}") from None
        if not (_HASH_RE.match(str(rev.attestation_id)) and _HASH_RE.match(str(rev.issuer))
                and re.fullmatch(r"[0-9a-f]{64}", str(rev.signed_by))
                and re.fullmatch(r"[0-9a-f]{128}", str(rev.sig))
                and isinstance(rev.issued_at, int) and not isinstance(rev.issued_at, bool)
                and (rev.reason is None or (isinstance(rev.reason, str) and len(rev.reason) <= 256))):
            raise ClaimError("malformed revocation")
        return rev


# --- verification --------------------------------------------------------------


@dataclass
class Check:
    ok: bool
    code: str | None = None
    error: str | None = None

    @classmethod
    def fail(cls, code: str, error: str) -> Check:
        return cls(False, code, error)


def issuer_key_check(issuer_chain: Sigchain, issuer: str, signed_by: str, now: int, issued_at: int | None = None) -> Check:
    """The signing key must be a non-master device of the issuer with sign_identity, valid for what it signed.

    A revoked device is out, unless it was revoked with `untrusted_since` T and this was issued before T: an honest
    attestation made before a compromise survives the replacement of the keys. (`issued_at` is the signer's own date,
    so T is the owners' judgment and not a proof.)
    """
    if issuer_chain.identity_hash != issuer:
        return Check.fail("issuer_mismatch", "Issuer chain does not match the issuer")
    if signed_by == issuer_chain.get_current_master_key():
        return Check.fail("issuer_key_not_authorized", "The master key may not sign attestations")
    status = issuer_chain.device_status(signed_by)
    if not status["known"]:
        return Check.fail("issuer_key_not_authorized", "Signing key is not an active device of the issuer")
    if status["revoked"]:
        since = status["untrusted_since"]
        if since is None or issued_at is None or issued_at >= since:
            return Check.fail("issuer_key_not_authorized", "Signing key was revoked")
    elif status["expires"] and status["expires"] < now:
        return Check.fail("issuer_key_not_authorized", "Signing key is not an active device of the issuer")
    if DeviceCapability.SIGN_IDENTITY.value not in status["capabilities"]:
        return Check.fail("issuer_key_not_authorized", "Signing key lacks the sign_identity capability")
    return Check(True)


def _verify_sig(pubkey_hex: str, message: bytes, sig_hex: str) -> bool:
    try:
        return VerifyKey.from_hex(pubkey_hex).verify_hex(message, sig_hex)
    except Exception:
        return False


# Self-contained proof verifiers, keyed by attestation method. Each takes
# (attestation, subject_chain, now) and returns a Check. Registered by
# nodetide.core.eidas when its optional dependencies are present.
PROOF_VERIFIERS: dict[str, Callable[[Attestation, Sigchain, int], Check]] = {}


def verify_attestation(
    att: Attestation,
    subject_chain: Sigchain,
    issuer_chain: Sigchain | None = None,
    now: int | None = None,
    resolve: Callable[[str], Sigchain | None] | None = None,
) -> Check:
    """Check an attestation against the holder's chain (and the issuer's, if issued).

    `resolve` (identity hash -> sigchain) is needed to check an issuer that is an organization with owners.

    Does not check revocation by the issuer (see AttestationRevocation) or
    whether the relying party trusts the issuer: that is policy.
    """
    now = int(time.time()) if now is None else now

    valid, err = subject_chain.verify(resolve)
    if not valid:
        return Check.fail("invalid_sigchain", err or "Invalid subject sigchain")
    if subject_chain.identity_hash != att.subject:
        return Check.fail("subject_mismatch", "Sigchain does not belong to the subject")

    # Behind, not wrong: the attestation was made against control state this chain does not have yet
    if not any(e.event_hash() == att.chain_head for e in subject_chain.events):
        return Check.fail("unknown_chain_head", "Attestation refers to a newer chain state; fetch the latest sigchain")

    record = subject_chain.get_claim(att.claim_id)
    if record is None:
        return Check.fail("unknown_claim", "The subject has no such claim")
    if record.claim_type != att.claim_type or record.commitment != att.commitment:
        return Check.fail("claim_mismatch", "Attestation does not match the claim on the chain")
    status = record.status(now)
    if status != "active":
        return Check.fail(f"claim_{status}", f"The claim is {status}")

    if att.issued_at > now + CLOCK_SKEW:
        return Check.fail("not_yet_valid", "Attestation is issued in the future")
    if now > att.expires_at:
        return Check.fail("expired", "Attestation has expired")
    if not any(e.event_hash() == att.chain_head for e in subject_chain.events):
        return Check.fail("unknown_chain_head", "Attestation refers to a newer chain state; fetch the latest sigchain")

    if att.proof is not None:
        verifier = PROOF_VERIFIERS.get(att.method)
        if verifier is None:
            return Check.fail("unsupported_method", f"No verifier for method {att.method}")
        return verifier(att, subject_chain, now)

    if issuer_chain is None:
        return Check.fail("unknown_issuer", "The issuer's sigchain is not available")
    valid, err = issuer_chain.verify(resolve)
    if not valid:
        return Check.fail("invalid_sigchain", err or "Invalid issuer sigchain")
    assert att.issuer and att.signed_by and att.sig
    key_check = issuer_key_check(issuer_chain, att.issuer, att.signed_by, now, att.issued_at)
    if not key_check.ok:
        return key_check
    if not _verify_sig(att.signed_by, att.signing_input(), att.sig):
        return Check.fail("bad_signature", "Attestation signature is invalid")
    return Check(True)


def verify_revocation(
    rev: AttestationRevocation, issuer_chain: Sigchain, now: int | None = None,
    resolve: Callable[[str], Sigchain | None] | None = None,
) -> Check:
    now = int(time.time()) if now is None else now
    valid, err = issuer_chain.verify(resolve)
    if not valid:
        return Check.fail("invalid_sigchain", err or "Invalid issuer sigchain")
    key_check = issuer_key_check(issuer_chain, rev.issuer, rev.signed_by, now, rev.issued_at)
    if not key_check.ok:
        return key_check
    if not _verify_sig(rev.signed_by, rev.signing_input(), rev.sig):
        return Check.fail("bad_signature", "Revocation signature is invalid")
    return Check(True)
