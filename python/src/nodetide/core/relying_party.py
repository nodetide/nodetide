"""Relying-party evaluation of presented claims ("Evaluating a claim" in identity-system.md).

A holder presents a claim document and an attestation for it. The relying party
applies its own ClaimRule: who may vouch for this kind of claim, how strongly,
and for how long. The same attestation can satisfy one party and be ignored by
another; nothing here is a global opinion about an issuer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from nodetide.core.claims import (
    ASSURANCE_LEVELS,
    Attestation,
    Check,
    ClaimDocument,
    verify_attestation,
)
from nodetide.core.identity import Sigchain, SocialRecoveryEvent

ASSURANCE_RANK = {level: i for i, level in enumerate(ASSURANCE_LEVELS)}


@dataclass(frozen=True)
class ClaimRule:
    """What this relying party accepts as proof of one claim type."""

    claim_type: str
    issuers: frozenset[str] = frozenset()   # identity hashes whose attestations count
    allow_proof: bool = False                # self-contained proofs (eIDAS qualified signatures)
    methods: frozenset[str] = frozenset()    # empty = any method
    min_assurance: str = "low"
    name_leniency: str = "transliterated"    # legal_name vs certificate: exact|transliterated|approximate
    max_age_days: int | None = None          # since the attestation was issued
    reject_if_recovered: bool = True         # holder's chain had a social recovery after the attestation

    def __post_init__(self) -> None:
        if self.min_assurance not in ASSURANCE_RANK:
            raise ValueError(f"unknown assurance level {self.min_assurance!r}")

    def describe(self) -> dict[str, Any]:
        """What an application should know to send something acceptable (no secrets)."""
        return {
            "claim_type": self.claim_type,
            "accepted_issuers": sorted(self.issuers),
            "accepts_proof": self.allow_proof,
            "methods": sorted(self.methods),
            "min_assurance": self.min_assurance,
        }


@dataclass
class VerifiedClaim:
    """A claim that passed a ClaimRule."""

    claim_type: str
    value: Any
    issuer: str | None
    method: str
    assurance: str
    issued_at: int
    expires_at: int
    attestation_id: str
    name_match: str | None = None


@dataclass
class Evaluation:
    claim: VerifiedClaim | None = None
    code: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.claim is not None

    @classmethod
    def fail(cls, code: str, error: str) -> Evaluation:
        return cls(code=code, error=error)


def recovered_since(chain: Sigchain, chain_head: str) -> bool:
    """Did a social recovery happen after the chain state `chain_head`?"""
    seen_head = False
    for event in chain.events:
        if seen_head and isinstance(event, SocialRecoveryEvent):
            return True
        if event.event_hash() == chain_head:
            seen_head = True
    return False


def evaluate_claim(
    rule: ClaimRule,
    document: ClaimDocument,
    attestation: Attestation,
    subject_chain: Sigchain,
    issuer_chain: Sigchain | None = None,
    *,
    revoked: bool = False,
    now: int | None = None,
    resolve=None,
) -> Evaluation:
    """Apply `rule` to a presented claim. Blocking when the attestation is a proof
    (it may consult revocation services): call it from an executor in async code."""
    now = int(time.time()) if now is None else now

    if document.claim_type != rule.claim_type or attestation.claim_type != rule.claim_type:
        return Evaluation.fail("wrong_claim_type", f"Not a {rule.claim_type} claim")
    if document.identity != attestation.subject or document.claim_id != attestation.claim_id:
        return Evaluation.fail("claim_mismatch", "The document and attestation are about different claims")
    if not document.matches(subject_chain.get_claim(document.claim_id)):
        return Evaluation.fail("claim_mismatch", "The document is not the claim on the identity's chain")

    if rule.methods and attestation.method not in rule.methods:
        return Evaluation.fail("method_not_accepted", f"Method {attestation.method} is not accepted")
    if ASSURANCE_RANK[attestation.assurance] < ASSURANCE_RANK[rule.min_assurance]:
        return Evaluation.fail("assurance_too_low", f"{rule.min_assurance} assurance or better is required")
    if attestation.proof is not None:
        if not rule.allow_proof:
            return Evaluation.fail("issuer_not_accepted", "Self-contained proofs are not accepted for this claim")
    elif attestation.issuer not in rule.issuers:
        return Evaluation.fail("issuer_not_accepted", "This issuer is not trusted for this claim")

    if revoked:
        return Evaluation.fail("revoked", "The issuer has revoked this attestation")
    if rule.max_age_days is not None and now - attestation.issued_at > rule.max_age_days * 86400:
        return Evaluation.fail("too_old", f"Older than {rule.max_age_days} days")
    if rule.reject_if_recovered and recovered_since(subject_chain, attestation.chain_head):
        return Evaluation.fail("recovered_since", "The identity was recovered after this was verified; verify again")

    check: Check = verify_attestation(attestation, subject_chain, issuer_chain, now, resolve)
    if not check.ok:
        return Evaluation.fail(check.code or "invalid_attestation", check.error or "Invalid attestation")

    name_match = None
    if attestation.proof is not None and rule.claim_type == "legal_name":
        from nodetide.eidas.verify import check_legal_name

        name = check_legal_name(attestation, document, rule.name_leniency)
        if not name.ok:
            return Evaluation.fail("name_mismatch", name.reason or "The name does not match the certificate")
        name_match = name.how

    return Evaluation(claim=VerifiedClaim(
        claim_type=rule.claim_type,
        value=document.value,
        issuer=attestation.issuer,
        method=attestation.method,
        assurance=attestation.assurance,
        issued_at=attestation.issued_at,
        expires_at=attestation.expires_at,
        attestation_id=attestation.id,
        name_match=name_match,
    ))
