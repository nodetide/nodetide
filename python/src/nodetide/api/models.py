"""API request and response models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# Error codes
class ErrorCode(str, Enum):
    INVALID_REQUEST = "invalid_request"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_SIGCHAIN = "invalid_sigchain"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    STALE_STATE = "stale_state"
    THRESHOLD_NOT_MET = "threshold_not_met"
    INTERNAL_ERROR = "internal_error"


@dataclass
class APIError:
    """API error response."""
    error: str
    message: str
    code: int
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "error": self.error,
            "message": self.message,
            "code": self.code,
        }
        if self.details:
            d["details"] = self.details
        return d


# Identity models

@dataclass
class CreateIdentityRequest:
    """Request to create identity (genesis event)."""
    event: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CreateIdentityRequest:
        return cls(event=data["event"])


@dataclass
class CreateIdentityResponse:
    """Response after creating identity."""
    identity_hash: str
    accepted: bool
    event_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_hash": self.identity_hash,
            "accepted": self.accepted,
            "event_hash": self.event_hash,
        }


@dataclass
class IdentityResponse:
    """Identity details response."""
    identity_hash: str
    name: str | None
    identity_type: str
    created_at: int
    is_local: bool
    devices: list[dict[str, Any]]
    recovery: dict[str, Any] | None
    sigchain_length: int
    sigchain: list[dict[str, Any]]
    verified: bool
    master_pubkey: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_hash": self.identity_hash,
            "name": self.name,
            "type": self.identity_type,
            "created_at": self.created_at,
            "is_local": self.is_local,
            "devices": self.devices,
            "recovery": self.recovery,
            "sigchain_length": self.sigchain_length,
            "sigchain": self.sigchain,
            "verified": self.verified,
            "master_pubkey": self.master_pubkey,
        }


@dataclass
class SubmitEventRequest:
    """Request to submit a signed event."""
    event: dict[str, Any]
    store_device_key: bool = False
    device_private_key_encrypted: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubmitEventRequest:
        return cls(
            event=data["event"],
            store_device_key=data.get("store_device_key", False),
            device_private_key_encrypted=data.get("device_private_key_encrypted"),
        )


@dataclass
class SubmitEventResponse:
    """Response after submitting event."""
    accepted: bool
    event_hash: str
    sigchain_length: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "event_hash": self.event_hash,
            "sigchain_length": self.sigchain_length,
        }


@dataclass
class SigchainResponse:
    """Full sigchain response."""
    identity_hash: str
    head_hash: str
    length: int
    events: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_hash": self.identity_hash,
            "head_hash": self.head_hash,
            "length": self.length,
            "events": self.events,
        }


# Session models

@dataclass
class CreateSessionRequest:
    """Request to create a session."""
    identity: str
    device_pubkey: str
    expires_in: int
    timestamp: int
    signature: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CreateSessionRequest:
        return cls(
            identity=data["identity"],
            device_pubkey=data["device_pubkey"],
            expires_in=data.get("expires_in", 3600),
            timestamp=data["timestamp"],
            signature=data["signature"],
        )


@dataclass
class SessionResponse:
    """Session creation response."""
    token: str
    expires_at: int
    identity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "expires_at": self.expires_at,
            "identity": self.identity,
        }


# Recovery models

@dataclass
class InitiateRecoveryRequest:
    """Request to initiate recovery."""
    new_pubkey: str
    new_encryption_pubkey: str
    initiated_by: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InitiateRecoveryRequest:
        return cls(
            new_pubkey=data["new_pubkey"],
            new_encryption_pubkey=data["new_encryption_pubkey"],
            initiated_by=data["initiated_by"],
        )


@dataclass
class RecoveryStatusResponse:
    """Recovery status response."""
    recovery_id: str
    identity: str
    status: str  # pending, complete, expired
    threshold: int
    collected: int
    signatures: list[dict[str, Any]]
    expires_at: int
    new_master_pubkey: str | None = None
    event_hash: str | None = None
    prev: str | None = None
    new_encryption_pubkey: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "recovery_id": self.recovery_id,
            "identity": self.identity,
            "status": self.status,
            "threshold": self.threshold,
            "collected": self.collected,
            "signatures": self.signatures,
            "expires_at": self.expires_at,
        }
        if self.prev:
            d["prev"] = self.prev
        if self.new_encryption_pubkey:
            d["new_encryption_pubkey"] = self.new_encryption_pubkey
        if self.new_master_pubkey:
            d["new_master_pubkey"] = self.new_master_pubkey
        if self.event_hash:
            d["event_hash"] = self.event_hash
        return d


@dataclass
class SubmitRecoverySignatureRequest:
    """Request to submit recovery signature."""
    trustee_identity: str
    signature: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubmitRecoverySignatureRequest:
        return cls(
            trustee_identity=data["trustee_identity"],
            signature=data["signature"],
        )


# Trust models

@dataclass
class CreateDelegationRequest:
    """Request to create trust delegation."""
    delegation: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CreateDelegationRequest:
        return cls(delegation=data["delegation"])


@dataclass
class TrustCalculationResponse:
    """Trust in an attestation issuer, from the caller's perspective."""
    subject: str
    claim_type: str | None
    trust_score: float
    paths: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "claim_type": self.claim_type,
            "trust_score": self.trust_score,
            "paths": self.paths,
        }


# Verify models

@dataclass
class VerifyRequest:
    """Request to verify a sigchain."""
    sigchain: list[dict[str, Any]]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerifyRequest:
        return cls(sigchain=data["sigchain"])


@dataclass
class VerifyResponse:
    """Sigchain verification response."""
    valid: bool
    identity_hash: str | None = None
    events: int = 0
    current_master: str | None = None
    active_devices: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        if self.valid:
            return {
                "valid": True,
                "identity_hash": self.identity_hash,
                "events": self.events,
                "current_master": self.current_master,
                "active_devices": self.active_devices,
            }
        else:
            return {
                "valid": False,
                "error": self.error,
            }
