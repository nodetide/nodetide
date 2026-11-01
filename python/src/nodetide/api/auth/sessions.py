"""API authentication - session management and signature verification."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import logging

from nodetide.core.crypto import VerifyKey, hash_hex
from nodetide.core.identity import Sigchain, DeviceCapability

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """Active session."""
    token: str
    identity: str
    device_pubkey: str
    created_at: int
    expires_at: int

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class SessionStore:
    """In-memory session store."""

    def __init__(self):
        self._sessions: dict[str, Session] = {}

    def create(
        self,
        identity: str,
        device_pubkey: str,
        expires_in: int = 3600,
    ) -> Session:
        """Create a new session."""
        token = f"sess_{secrets.token_urlsafe(32)}"
        now = int(time.time())

        session = Session(
            token=token,
            identity=identity,
            device_pubkey=device_pubkey,
            created_at=now,
            expires_at=now + expires_in,
        )

        self._sessions[token] = session
        return session

    def get(self, token: str) -> Session | None:
        """Get a session by token."""
        session = self._sessions.get(token)
        if session and session.is_expired:
            self.delete(token)
            return None
        return session

    def delete(self, token: str) -> bool:
        """Delete a session."""
        if token in self._sessions:
            del self._sessions[token]
            return True
        return False

    def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns count removed."""
        expired = [
            token for token, session in self._sessions.items()
            if session.is_expired
        ]
        for token in expired:
            del self._sessions[token]
        return len(expired)


@dataclass
class AuthContext:
    """Authentication context for a request."""
    identity: str | None = None
    device_pubkey: str | None = None
    session: Session | None = None
    is_authenticated: bool = False
    capabilities: list[str] = field(default_factory=list)


def verify_event_signature(
    event: dict[str, Any],
    sigchain: Sigchain | None = None,
) -> tuple[bool, str | None]:
    """Verify an event's signature.

    For genesis events, verify self-signature.
    For other events, verify against sigchain.

    Returns (is_valid, error_message).
    """
    event_type = event.get("type")
    signature = event.get("signature")
    signed_by = event.get("signed_by")

    if signed_by == "owners":
        # Decided by the owners of an organization: their approvals are checked with the whole chain
        return (True, None) if event_type != "genesis" else (False, "Genesis must be self-signed")

    if not signature:
        return False, "Missing signature"

    if not signed_by:
        return False, "Missing signed_by"

    # Build signable dict (event without signature)
    signable = {k: v for k, v in event.items() if k not in ("signature", "approvals")}
    signable_json = json.dumps(signable, sort_keys=True, separators=(",", ":"))

    try:
        verify_key = VerifyKey.from_hex(signed_by)
    except Exception as e:
        return False, f"Invalid signed_by key: {e}"

    # Verify signature
    if not verify_key.verify_hex(signable_json.encode("utf-8"), signature):
        return False, "Signature verification failed"

    # For genesis, signed_by must equal pubkey (self-signed)
    if event_type == "genesis":
        if signed_by != event.get("pubkey"):
            return False, "Genesis must be self-signed"
        return True, None

    # For other events, verify signer is authorized
    if sigchain is None:
        return False, "Sigchain required for non-genesis events"

    current_master = sigchain.get_current_master_key()

    # Master key can do anything
    if signed_by == current_master:
        return True, None

    # Check if signed by active device with required capability
    active_devices = sigchain.get_active_devices()
    for device in active_devices:
        if device.pubkey == signed_by:
            # Check capability based on event type
            required_cap = get_required_capability(event_type)
            if required_cap and required_cap not in device.capabilities:
                return False, f"Device lacks required capability: {required_cap}"
            return True, None

    return False, "Signer not authorized"


def get_required_capability(event_type: str) -> str | None:
    """Get required capability for an event type."""
    capability_map = {
        "add_device": DeviceCapability.SIGN_IDENTITY.value,
        "revoke_device": DeviceCapability.SIGN_IDENTITY.value,
        "rotate_master": None,  # master key only
        "set_recovery": None,   # master key only
        "add_claim": DeviceCapability.MANAGE_CLAIMS.value,
        "revoke_claim": DeviceCapability.MANAGE_CLAIMS.value,
        "set_claim_order": DeviceCapability.MANAGE_CLAIMS.value,
    }
    return capability_map.get(event_type)


def verify_session_request(
    request: dict[str, Any],
    sigchain: Sigchain,
) -> tuple[bool, str | None]:
    """Verify a session creation request signature.

    Returns (is_valid, error_message).
    """
    signature = request.get("signature")
    device_pubkey = request.get("device_pubkey")
    timestamp = request.get("timestamp", 0)

    if not signature:
        return False, "Missing signature"

    if not device_pubkey:
        return False, "Missing device_pubkey"

    # Check timestamp freshness (within 5 minutes)
    now = int(time.time())
    if abs(now - timestamp) > 300:
        return False, "Timestamp too old or in future"

    # Build signable
    signable = {k: v for k, v in request.items() if k != "signature"}
    signable_json = json.dumps(signable, sort_keys=True, separators=(",", ":"))

    # Verify signer is master or active device
    current_master = sigchain.get_current_master_key()
    active_devices = sigchain.get_active_devices()

    valid_keys = [current_master] if current_master else []
    valid_keys.extend(d.pubkey for d in active_devices)

    if device_pubkey not in valid_keys:
        return False, "Device key not authorized"

    try:
        verify_key = VerifyKey.from_hex(device_pubkey)
        if not verify_key.verify_hex(signable_json.encode("utf-8"), signature):
            return False, "Signature verification failed"
    except Exception as e:
        return False, f"Signature error: {e}"

    return True, None


def extract_bearer_token(authorization: str | None) -> str | None:
    """Extract bearer token from Authorization header."""
    if not authorization:
        return None

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return parts[1]


@dataclass
class PendingRecovery:
    """A pending recovery operation."""
    recovery_id: str
    identity: str
    new_pubkey: str
    new_encryption_pubkey: str
    initiated_by: str
    initiated_at: int
    expires_at: int
    threshold: int
    trustees: list[str]
    signatures: dict[str, dict[str, Any]] = field(default_factory=dict)  # trustee -> {signature, signed_at}

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def collected(self) -> int:
        return len(self.signatures)

    @property
    def is_complete(self) -> bool:
        return self.collected >= self.threshold


class RecoveryStore:
    """Store for pending recoveries."""

    def __init__(self):
        self._recoveries: dict[str, PendingRecovery] = {}  # recovery_id -> recovery

    def create(
        self,
        identity: str,
        new_pubkey: str,
        new_encryption_pubkey: str,
        initiated_by: str,
        threshold: int,
        trustees: list[str],
        expires_in: int = 86400,  # 24 hours default
    ) -> PendingRecovery:
        """Create a new pending recovery."""
        recovery_id = f"rec_{secrets.token_urlsafe(16)}"
        now = int(time.time())

        recovery = PendingRecovery(
            recovery_id=recovery_id,
            identity=identity,
            new_pubkey=new_pubkey,
            new_encryption_pubkey=new_encryption_pubkey,
            initiated_by=initiated_by,
            initiated_at=now,
            expires_at=now + expires_in,
            threshold=threshold,
            trustees=trustees,
        )

        self._recoveries[recovery_id] = recovery
        return recovery

    def get(self, recovery_id: str) -> PendingRecovery | None:
        """Get a pending recovery."""
        recovery = self._recoveries.get(recovery_id)
        if recovery and recovery.is_expired:
            self.delete(recovery_id)
            return None
        return recovery

    def get_for_identity(self, identity: str) -> list[PendingRecovery]:
        """Get all pending recoveries for an identity."""
        return [
            r for r in self._recoveries.values()
            if r.identity == identity and not r.is_expired
        ]

    def add_signature(
        self,
        recovery_id: str,
        trustee: str,
        signature: str,
    ) -> PendingRecovery | None:
        """Add a trustee signature to a recovery."""
        recovery = self.get(recovery_id)
        if not recovery:
            return None

        if trustee not in recovery.trustees:
            return None

        if trustee in recovery.signatures:
            # Already signed
            return recovery

        recovery.signatures[trustee] = {
            "signature": signature,
            "signed_at": int(time.time()),
        }

        return recovery

    def delete(self, recovery_id: str) -> bool:
        """Delete a recovery."""
        if recovery_id in self._recoveries:
            del self._recoveries[recovery_id]
            return True
        return False

    def cleanup_expired(self) -> int:
        """Remove expired recoveries."""
        expired = [
            rid for rid, r in self._recoveries.items()
            if r.is_expired
        ]
        for rid in expired:
            del self._recoveries[rid]
        return len(expired)
