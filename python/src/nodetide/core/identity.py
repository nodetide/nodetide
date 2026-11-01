"""Identity and sigchain implementation.

Identity = hash(genesis event)
Sigchain = append-only log of signed events
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from nodetide.core.merkle import EMPTY_ROOT, merkle_proof, merkle_root, verify_proof
from nodetide.core.crypto import (
    KeyPair,
    VerifyKey,
    PublicKeyBundle,
    SigningKey,
    hash_json,
    hash_hex,
    DEFAULT_HASH_ALG,
    DEFAULT_SIGN_ALG,
)


class EventType(str, Enum):
    """Sigchain event types."""

    GENESIS = "genesis"
    ADD_DEVICE = "add_device"
    REVOKE_DEVICE = "revoke_device"
    ROTATE_MASTER = "rotate_master"
    SET_RECOVERY = "set_recovery"
    SOCIAL_RECOVERY = "social_recovery"
    RESOLVE_FORK = "resolve_fork"
    SET_DISTRIBUTION = "set_distribution"
    ADD_CLAIM = "add_claim"
    REVOKE_CLAIM = "revoke_claim"
    SET_CLAIM_ORDER = "set_claim_order"
    SET_OWNERS = "set_owners"
    CHECKPOINT = "checkpoint"


class IdentityType(str, Enum):
    """Identity types."""

    PERSONAL = "personal"
    ORGANIZATION = "organization"
    EPHEMERAL = "ephemeral"


class DeviceCapability(str, Enum):
    """Device key capabilities."""

    SIGN_MESSAGES = "sign_messages"
    SIGN_FILES = "sign_files"
    SIGN_IDENTITY = "sign_identity"
    ENCRYPT = "encrypt"
    AUTHENTICATE = "authenticate"  # may sign AuthAssertions (SSO login)
    MANAGE_CLAIMS = "manage_claims"  # may add and revoke this identity's claims


@dataclass
class SigchainEvent:
    """Base sigchain event."""

    type: EventType
    timestamp: int
    prev: str | None  # hash of previous event, None for genesis
    signature: str
    signed_by: str  # public key hex that signed this
    version: int = 1
    alg: str = DEFAULT_SIGN_ALG
    hash_alg: str = DEFAULT_HASH_ALG
    # Owner approvals (organization identities): see "Organization identities" below. Part of the event hash, not of
    # what anyone signs, so approvals can be collected one after another.
    approvals: list[dict[str, str]] | None = None
    # Control events: a commitment to the first `count` content events, {"count": n, "root": merkle root} (sigchain-v2.md)
    content: dict[str, Any] | None = None
    # Content events: position in the content track and the control event they were signed under
    seq: int | None = None
    control_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = {
            "version": self.version,
            "type": self.type.value,
            "alg": self.alg,
            "hash_alg": self.hash_alg,
            "timestamp": self.timestamp,
            "prev": self.prev,
            "signature": self.signature,
            "signed_by": self.signed_by,
        }
        if self.approvals is not None:  # absent for ordinary events, so existing hashes do not change
            d["approvals"] = self.approvals
        if self.content is not None:
            d["content"] = self.content
        if self.seq is not None:
            d["seq"] = self.seq
            d["control_ref"] = self.control_ref
        return d

    def signable_dict(self) -> dict[str, Any]:
        """Get dictionary for signing (excludes the signature and the owner approvals)."""
        d = self.to_dict()
        del d["signature"]
        d.pop("approvals", None)
        return d

    def event_hash(self) -> str:
        """Hash of this event."""
        return hash_json(self.to_dict(), self.hash_alg)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SigchainEvent:
        """Load from dictionary. Dispatches to appropriate subclass."""
        event_type = EventType(data["type"])

        event_classes = {
            EventType.GENESIS: GenesisEvent,
            EventType.ADD_DEVICE: AddDeviceEvent,
            EventType.REVOKE_DEVICE: RevokeDeviceEvent,
            EventType.ROTATE_MASTER: RotateMasterEvent,
            EventType.SET_RECOVERY: SetRecoveryEvent,
            EventType.SOCIAL_RECOVERY: SocialRecoveryEvent,
            EventType.RESOLVE_FORK: ResolveForkEvent,
            EventType.SET_DISTRIBUTION: SetDistributionEvent,
            EventType.ADD_CLAIM: AddClaimEvent,
            EventType.REVOKE_CLAIM: RevokeClaimEvent,
            EventType.SET_CLAIM_ORDER: SetClaimOrderEvent,
            EventType.SET_OWNERS: SetOwnersEvent,
            EventType.CHECKPOINT: CheckpointEvent,
        }

        event_class = event_classes.get(event_type)
        if event_class is None:
            raise ValueError(f"Unknown event type: {event_type}")

        event = event_class._from_dict(data)
        if data.get("approvals") is not None:
            event.approvals = [dict(a) for a in data["approvals"]]
        if data.get("content") is not None:
            event.content = dict(data["content"])
        if data.get("seq") is not None:
            event.seq = data["seq"]
            event.control_ref = data.get("control_ref")
        return event


@dataclass(kw_only=True)
class GenesisEvent(SigchainEvent):
    """Genesis event - creates a new identity."""

    pubkey: str  # master public key hex
    encryption_pubkey: str  # encryption public key hex
    identity_type: IdentityType = IdentityType.PERSONAL
    name: str | None = None  # optional display name
    ephemeral: bool = False
    ownership_proof: str | None = None  # for ephemeral, link to persistent identity
    distribution_points: list[str] | None = None  # initial distribution endpoints
    owners: list[dict[str, Any]] | None = None  # organization identities: [{"identity", "weight"}], see below
    governance: str | None = None  # with owners: "self" (default) or "managed", see below; fixed for the identity's life

    def __post_init__(self):
        self.type = EventType.GENESIS
        self.prev = None

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "pubkey": self.pubkey,
            "encryption_pubkey": self.encryption_pubkey,
            "identity_type": self.identity_type.value,
            "name": self.name,
            "ephemeral": self.ephemeral,
            "ownership_proof": self.ownership_proof,
            "distribution_points": self.distribution_points,
        })
        if self.owners is not None:
            d["owners"] = self.owners
        if self.governance is not None:
            d["governance"] = self.governance
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> GenesisEvent:
        return cls(
            type=EventType.GENESIS,
            timestamp=data["timestamp"],
            prev=None,
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            pubkey=data["pubkey"],
            encryption_pubkey=data["encryption_pubkey"],
            identity_type=IdentityType(data.get("identity_type", "personal")),
            name=data.get("name"),
            ephemeral=data.get("ephemeral", False),
            ownership_proof=data.get("ownership_proof"),
            distribution_points=data.get("distribution_points"),
            owners=data.get("owners"),
            governance=data.get("governance"),
        )

    @classmethod
    def create(
        cls,
        keypair: KeyPair,
        identity_type: IdentityType = IdentityType.PERSONAL,
        name: str | None = None,
        ephemeral: bool = False,
        ownership_proof: str | None = None,
        distribution_points: list[str] | None = None,
        owners: list[dict[str, Any]] | None = None,
        governance: str | None = None,
    ) -> GenesisEvent:
        """Create and sign a new genesis event."""
        event = cls(
            type=EventType.GENESIS,
            timestamp=int(time.time()),
            prev=None,
            signature="",  # will be set below
            signed_by=keypair.verify_key.to_hex(),
            pubkey=keypair.verify_key.to_hex(),
            encryption_pubkey=keypair.public_encryption_key.to_hex(),
            identity_type=identity_type,
            name=name,
            ephemeral=ephemeral,
            ownership_proof=ownership_proof,
            distribution_points=distribution_points,
            owners=owners,
            governance=governance,
        )
        # Sign the event
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class AddDeviceEvent(SigchainEvent):
    """Add a device key to the identity."""

    device_pubkey: str
    device_encryption_pubkey: str
    label: str
    capabilities: list[str] = field(default_factory=lambda: [c.value for c in DeviceCapability])
    expires: int | None = None  # optional expiration timestamp

    def __post_init__(self):
        self.type = EventType.ADD_DEVICE

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "device_pubkey": self.device_pubkey,
            "device_encryption_pubkey": self.device_encryption_pubkey,
            "label": self.label,
            "capabilities": self.capabilities,
            "expires": self.expires,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> AddDeviceEvent:
        return cls(
            type=EventType.ADD_DEVICE,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            device_pubkey=data["device_pubkey"],
            device_encryption_pubkey=data["device_encryption_pubkey"],
            label=data["label"],
            capabilities=data.get("capabilities", [c.value for c in DeviceCapability]),
            expires=data.get("expires"),
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        device_keypair: KeyPair,
        label: str,
        prev_hash: str,
        capabilities: list[DeviceCapability] | None = None,
        expires: int | None = None,
        content: dict | None = None,
    ) -> AddDeviceEvent:
        """Create and sign an add device event."""
        return cls.create_for(
            master_keypair,
            device_keypair.verify_key.to_hex(),
            device_keypair.public_encryption_key.to_hex(),
            label,
            prev_hash,
            capabilities,
            expires,
            content,
        )

    @classmethod
    def create_for(
        cls,
        master_keypair: KeyPair,
        device_pubkey: str,
        device_encryption_pubkey: str,
        label: str,
        prev_hash: str,
        capabilities: list[DeviceCapability] | None = None,
        expires: int | None = None,
        content: dict | None = None,
    ) -> AddDeviceEvent:
        """Create and sign an add device event for a device whose public keys we were given (it keeps its private keys)."""
        caps = [c.value for c in capabilities] if capabilities else [c.value for c in DeviceCapability]
        event = cls(
            content=content,
            type=EventType.ADD_DEVICE,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            device_pubkey=device_pubkey,
            device_encryption_pubkey=device_encryption_pubkey,
            label=label,
            capabilities=caps,
            expires=expires,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class RevokeDeviceEvent(SigchainEvent):
    """Revoke a device key."""

    device_pubkey: str
    reason: str | None = None

    def __post_init__(self):
        self.type = EventType.REVOKE_DEVICE

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "device_pubkey": self.device_pubkey,
            "reason": self.reason,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> RevokeDeviceEvent:
        return cls(
            type=EventType.REVOKE_DEVICE,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            device_pubkey=data["device_pubkey"],
            reason=data.get("reason"),
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        device_pubkey: str,
        prev_hash: str,
        reason: str | None = None,
        content: dict | None = None,
    ) -> RevokeDeviceEvent:
        """Create and sign a revoke device event."""
        event = cls(
            content=content,
            type=EventType.REVOKE_DEVICE,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            device_pubkey=device_pubkey,
            reason=reason,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class RotateMasterEvent(SigchainEvent):
    """Rotate the master key."""

    new_pubkey: str
    new_encryption_pubkey: str

    def __post_init__(self):
        self.type = EventType.ROTATE_MASTER

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "new_pubkey": self.new_pubkey,
            "new_encryption_pubkey": self.new_encryption_pubkey,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> RotateMasterEvent:
        return cls(
            type=EventType.ROTATE_MASTER,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            new_pubkey=data["new_pubkey"],
            new_encryption_pubkey=data["new_encryption_pubkey"],
        )

    @classmethod
    def create(
        cls,
        old_keypair: KeyPair,
        new_keypair: KeyPair,
        prev_hash: str,
        content: dict | None = None,
    ) -> RotateMasterEvent:
        """Create and sign a master key rotation event."""
        event = cls(
            content=content,
            type=EventType.ROTATE_MASTER,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=old_keypair.verify_key.to_hex(),
            new_pubkey=new_keypair.verify_key.to_hex(),
            new_encryption_pubkey=new_keypair.public_encryption_key.to_hex(),
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = old_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class SetRecoveryEvent(SigchainEvent):
    """Set or update recovery trustees."""

    primary_trustees: list[str]  # identity hashes
    primary_threshold: int
    backup_trustees: list[str] | None = None
    backup_threshold: int | None = None
    backup_activates_after: int | None = None  # seconds

    def __post_init__(self):
        self.type = EventType.SET_RECOVERY

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "primary_trustees": self.primary_trustees,
            "primary_threshold": self.primary_threshold,
            "backup_trustees": self.backup_trustees,
            "backup_threshold": self.backup_threshold,
            "backup_activates_after": self.backup_activates_after,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> SetRecoveryEvent:
        return cls(
            type=EventType.SET_RECOVERY,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            primary_trustees=data["primary_trustees"],
            primary_threshold=data["primary_threshold"],
            backup_trustees=data.get("backup_trustees"),
            backup_threshold=data.get("backup_threshold"),
            backup_activates_after=data.get("backup_activates_after"),
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        prev_hash: str,
        primary_trustees: list[str],
        primary_threshold: int,
        backup_trustees: list[str] | None = None,
        backup_threshold: int | None = None,
        backup_activates_after: int | None = None,
        content: dict | None = None,
    ) -> SetRecoveryEvent:
        """Create and sign a set recovery event."""
        event = cls(
            content=content,
            type=EventType.SET_RECOVERY,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            primary_trustees=primary_trustees,
            primary_threshold=primary_threshold,
            backup_trustees=backup_trustees,
            backup_threshold=backup_threshold,
            backup_activates_after=backup_activates_after,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass
class RecoverySignature:
    """A trustee's signature for social recovery."""

    trustee_identity: str
    signature: str


@dataclass(kw_only=True)
class SocialRecoveryEvent(SigchainEvent):
    """Social recovery - threshold of trustees restore access."""

    new_pubkey: str
    new_encryption_pubkey: str
    recovery_signatures: list[dict[str, str]]  # list of {trustee_identity, signature}

    def __post_init__(self):
        self.type = EventType.SOCIAL_RECOVERY

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "new_pubkey": self.new_pubkey,
            "new_encryption_pubkey": self.new_encryption_pubkey,
            "recovery_signatures": self.recovery_signatures,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> SocialRecoveryEvent:
        return cls(
            type=EventType.SOCIAL_RECOVERY,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            new_pubkey=data["new_pubkey"],
            new_encryption_pubkey=data["new_encryption_pubkey"],
            recovery_signatures=data["recovery_signatures"],
        )


@dataclass(kw_only=True)
class SetOwnersEvent(SigchainEvent):
    """Replace the owners of an organization identity (decided by the current owners, by the usual rule)."""

    owners: list[dict[str, Any]]  # [{"identity", "weight"}]

    def __post_init__(self):
        self.type = EventType.SET_OWNERS

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["owners"] = self.owners
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> SetOwnersEvent:
        return cls(
            type=EventType.SET_OWNERS,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            owners=data["owners"],
        )


@dataclass(kw_only=True)
class ResolveForkEvent(SigchainEvent):
    """Resolve a fork by choosing a branch."""

    chosen_branch_hash: str  # hash of the event to continue from
    rejected_branch_hash: str  # hash of the rejected event

    def __post_init__(self):
        self.type = EventType.RESOLVE_FORK

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "chosen_branch_hash": self.chosen_branch_hash,
            "rejected_branch_hash": self.rejected_branch_hash,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> ResolveForkEvent:
        return cls(
            type=EventType.RESOLVE_FORK,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            chosen_branch_hash=data["chosen_branch_hash"],
            rejected_branch_hash=data["rejected_branch_hash"],
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        prev_hash: str,
        chosen_branch_hash: str,
        rejected_branch_hash: str,
        content: dict | None = None,
    ) -> ResolveForkEvent:
        """Create and sign a fork resolution event."""
        event = cls(
            content=content,
            type=EventType.RESOLVE_FORK,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            chosen_branch_hash=chosen_branch_hash,
            rejected_branch_hash=rejected_branch_hash,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class SetDistributionEvent(SigchainEvent):
    """Update distribution points for the identity."""

    distribution_points: list[str]  # list of endpoint URIs

    def __post_init__(self):
        self.type = EventType.SET_DISTRIBUTION

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "distribution_points": self.distribution_points,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> SetDistributionEvent:
        return cls(
            type=EventType.SET_DISTRIBUTION,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            distribution_points=data["distribution_points"],
        )

    @classmethod
    def create(
        cls,
        master_keypair: KeyPair,
        prev_hash: str,
        distribution_points: list[str],
        content: dict | None = None,
    ) -> SetDistributionEvent:
        """Create and sign a set distribution event."""
        event = cls(
            content=content,
            type=EventType.SET_DISTRIBUTION,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=master_keypair.verify_key.to_hex(),
            distribution_points=distribution_points,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = master_keypair.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class AddClaimEvent(SigchainEvent):
    """Commit to a claim about this identity. The value itself stays off-chain."""

    claim_id: str
    claim_type: str
    commitment: str  # hex hash binding claim_id, type, salt and value
    expires: int | None = None

    def __post_init__(self):
        self.type = EventType.ADD_CLAIM

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "commitment": self.commitment,
            "expires": self.expires,
        })
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> AddClaimEvent:
        return cls(
            type=EventType.ADD_CLAIM,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            claim_id=data["claim_id"],
            claim_type=data["claim_type"],
            commitment=data["commitment"],
            expires=data.get("expires"),
        )

    @classmethod
    def create(
        cls,
        signer: KeyPair | SigningKey,
        prev_hash: str,
        claim_id: str,
        claim_type: str,
        commitment: str,
        expires: int | None = None,
        *,
        seq: int = 0,
        control_ref: str | None = None,
    ) -> AddClaimEvent:
        """Create and sign an add-claim event (signer: master or manage_claims device).

        A content event: `prev_hash` is the previous CONTENT event (None for the first), `seq` its position and
        `control_ref` the latest control event (the chain head) it is signed under.
        """
        event = cls(
            type=EventType.ADD_CLAIM,
            timestamp=int(time.time()),
            prev=prev_hash,
            seq=seq,
            control_ref=control_ref,
            signature="",
            signed_by=signer.verify_key.to_hex(),
            claim_id=claim_id,
            claim_type=claim_type,
            commitment=commitment,
            expires=expires,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = signer.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class SetClaimOrderEvent(SigchainEvent):
    """Say which claims of one type come first: the first is the holder's default (their preferred email, say).

    Only claim ids are listed, so the event reveals nothing the add_claim events did not. The newest event for a
    claim type wins; claims it does not list follow in the order they were made.
    """

    claim_type: str
    order: list[str]

    MAX_ORDER = 32

    def __post_init__(self):
        self.type = EventType.SET_CLAIM_ORDER

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({"claim_type": self.claim_type, "order": list(self.order)})
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> SetClaimOrderEvent:
        return cls(
            type=EventType.SET_CLAIM_ORDER,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            claim_type=data["claim_type"],
            order=list(data["order"]),
        )

    @classmethod
    def create(
        cls, signer: KeyPair | SigningKey, prev_hash: str | None, claim_type: str, order: list[str],
        *, seq: int = 0, control_ref: str | None = None,
    ) -> SetClaimOrderEvent:
        """Create and sign an order event (signer: master or manage_claims device). A content event, see AddClaimEvent."""
        event = cls(
            type=EventType.SET_CLAIM_ORDER,
            timestamp=int(time.time()),
            prev=prev_hash,
            seq=seq,
            control_ref=control_ref,
            signature="",
            signed_by=signer.verify_key.to_hex(),
            claim_type=claim_type,
            order=list(order),
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = signer.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class RevokeClaimEvent(SigchainEvent):
    """Withdraw a claim."""

    claim_id: str
    reason: str | None = None

    def __post_init__(self):
        self.type = EventType.REVOKE_CLAIM

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({"claim_id": self.claim_id, "reason": self.reason})
        return d

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> RevokeClaimEvent:
        return cls(
            type=EventType.REVOKE_CLAIM,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
            claim_id=data["claim_id"],
            reason=data.get("reason"),
        )

    @classmethod
    def create(
        cls,
        signer: KeyPair | SigningKey,
        prev_hash: str,
        claim_id: str,
        reason: str | None = None,
        content: dict | None = None,
    ) -> RevokeClaimEvent:
        """Create and sign a revoke-claim event."""
        event = cls(
            content=content,
            type=EventType.REVOKE_CLAIM,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=signer.verify_key.to_hex(),
            claim_id=claim_id,
            reason=reason,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = signer.sign_hex(signable.encode("utf-8"))
        return event


@dataclass(kw_only=True)
class CheckpointEvent(SigchainEvent):
    """Commit to the content events so far (the `content` field), changing nothing else.

    Signed by the master key or a device with manage_claims. Needed when content was added and no other control
    event has committed it yet: a light verifier can only rely on content that a control event commits to.
    """

    def __post_init__(self):
        self.type = EventType.CHECKPOINT

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> CheckpointEvent:
        return cls(
            type=EventType.CHECKPOINT,
            timestamp=data["timestamp"],
            prev=data["prev"],
            signature=data["signature"],
            signed_by=data["signed_by"],
            version=data.get("version", 1),
            alg=data.get("alg", DEFAULT_SIGN_ALG),
            hash_alg=data.get("hash_alg", DEFAULT_HASH_ALG),
        )

    @classmethod
    def create(cls, signer: KeyPair | SigningKey, prev_hash: str, content: dict[str, Any]) -> CheckpointEvent:
        event = cls(
            type=EventType.CHECKPOINT,
            timestamp=int(time.time()),
            prev=prev_hash,
            signature="",
            signed_by=signer.verify_key.to_hex(),
            content=content,
        )
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        event.signature = signer.sign_hex(signable.encode("utf-8"))
        return event


CONTENT_TYPES = (EventType.ADD_CLAIM, EventType.SET_CLAIM_ORDER)


@dataclass
class ClaimRecord:
    """A claim as recorded on a sigchain, with its current status."""

    claim_id: str
    claim_type: str
    commitment: str
    created_at: int
    expires: int | None
    event_hash: str
    signed_by: str
    revoked_at: int | None = None
    revoke_reason: str | None = None

    def status(self, at_time: int | None = None) -> str:
        if self.revoked_at is not None:
            return "revoked"
        if self.expires and self.expires < (int(time.time()) if at_time is None else at_time):
            return "expired"
        return "active"


@dataclass
class DeviceInfo:
    """Information about an active device."""

    pubkey: str
    encryption_pubkey: str
    label: str
    capabilities: list[str]
    added_at: int
    expires: int | None


# --- Organization identities -------------------------------------------------------------------------------------
#
# An organization identity is owned by other (personal) identities, each with a weight. The genesis declares the owners
# and carries the approval of every one of them; the organization's own key signs it like any genesis. Two modes,
# chosen in the genesis and fixed for the organization's life (`governance`):
#
#   "self" (default)  the organization runs itself with its own key: devices, claims and distribution points are
#                     ordinary events signed by it, and it may rotate itself. Owners are needed only to recover the
#                     key when it is lost or taken (rotate_master) and to change the owners (set_owners). Right for
#                     automated organizations (a verification service) whose activity should not involve owner keys.
#   "managed"         the owners also decide every change of devices: add_device and revoke_device need their approval
#                     and the organization's own key cannot make them (nor rotate itself). Right where the owners
#                     want control of who acts for the organization.
#
# Events the owners decide are "governed": signed_by == GOVERNED, no signature of their own, only owner approvals,
# valid when the approving owners' weights add up to MORE than half of all declared weights. The owners and weights in
# force are those declared before the event, so a change cannot vote itself in.
#
# An approval names the owner's identity and the head of the owner's chain at signing time ("state"). It is checked
# against the owner's master key AS OF that state, so an owner who later rotates or recovers their key does not
# invalidate old organization events, and recovering an owner (social recovery) needs no organization event at all.
# When a node accepts a new event it also requires that key to be the owner's CURRENT key (check_current), so a key
# an owner has since replaced can no longer sign.

GOVERNED = "owners"
MAX_OWNERS = 16
MAX_OWNER_WEIGHT = 1_000_000
GOVERNED_TYPES = (EventType.ROTATE_MASTER, EventType.SET_OWNERS)  # in every mode
MANAGED_TYPES = GOVERNED_TYPES + (EventType.ADD_DEVICE, EventType.REVOKE_DEVICE)  # "managed": devices too
GOVERNANCE_MODES = ("self", "managed")

ChainResolver = Callable[[str], "Sigchain | None"]


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def approval_message(event: SigchainEvent, owner_identity: str, state: str) -> bytes:
    """What an owner signs to approve an event: the event body, bound to the owner and the chain state used."""
    return _canonical({
        "purpose": "nodetide-owner-approval-v1",
        "owner": owner_identity,
        "state": state,
        "event": event.signable_dict(),
    })


def approve(event: SigchainEvent, owner_identity: str, owner_keypair: KeyPair, owner_state: str) -> dict[str, str]:
    """Add (or replace) one owner's approval on an event. `owner_state` is the head hash of the owner's own chain."""
    approval = {
        "identity": owner_identity,
        "state": owner_state,
        "key": owner_keypair.verify_key.to_hex(),
        "signature": owner_keypair.sign_hex(approval_message(event, owner_identity, owner_state)),
    }
    event.approvals = [a for a in (event.approvals or []) if a.get("identity") != owner_identity] + [approval]
    return approval


def propose_governed(event_cls: type[SigchainEvent], prev_hash: str, **fields: Any) -> SigchainEvent:
    """Build an unsigned governed event; owners add approvals with `approve`."""
    return event_cls(
        type=EventType.GENESIS,  # replaced by the class's __post_init__
        timestamp=int(time.time()),
        prev=prev_hash,
        signature="",
        signed_by=GOVERNED,
        approvals=[],
        **fields,
    )


def master_key_at(chain: Sigchain, state: str) -> str | None:
    """The master key of `chain` right after the event whose hash is `state` (None if the chain has no such event)."""
    key = None
    for event in chain.events:
        if isinstance(event, GenesisEvent):
            key = event.pubkey
        elif isinstance(event, (RotateMasterEvent, SocialRecoveryEvent)):
            key = event.new_pubkey
        if event.event_hash() == state:
            return key
    return None


def check_owner_list(owners: Any, resolve: ChainResolver | None) -> str | None:
    """Why a declared owner list is unusable, or None. Owners must be known personal identities."""
    if not isinstance(owners, list) or not 1 <= len(owners) <= MAX_OWNERS:
        return f"an organization has between 1 and {MAX_OWNERS} owners"
    seen: set[str] = set()
    for owner in owners:
        if not isinstance(owner, dict) or set(owner) != {"identity", "weight"}:
            return "an owner is {identity, weight}"
        identity, weight = owner["identity"], owner["weight"]
        if not isinstance(identity, str) or not identity:
            return "an owner needs an identity hash"
        if isinstance(weight, bool) or not isinstance(weight, int) or not 1 <= weight <= MAX_OWNER_WEIGHT:
            return f"an owner's weight is a whole number from 1 to {MAX_OWNER_WEIGHT}"
        if identity in seen:
            return "an owner is listed twice"
        seen.add(identity)
        if resolve is None:
            return "owner identities are needed to check an organization"
        chain = resolve(identity)
        genesis = chain.genesis if chain else None
        if genesis is None:
            return f"unknown owner identity {identity[:12]}"
        if genesis.identity_type != IdentityType.PERSONAL or genesis.owners is not None:
            return "an owner must be a personal identity"
    return None


def approval_score(
    event: SigchainEvent,
    owners: list[dict[str, Any]],
    resolve: ChainResolver | None,
    check_current: bool = False,
) -> tuple[int, int, str | None]:
    """(approved weight, total weight, error) for the approvals on an event."""
    total = sum(o["weight"] for o in owners)
    weights = {o["identity"]: o["weight"] for o in owners}
    approvals = event.approvals or []
    if resolve is None:
        return 0, total, "owner identities are needed to check an organization"
    done: set[str] = set()
    approved = 0
    for a in approvals:
        identity = a.get("identity") if isinstance(a, dict) else None
        if identity not in weights:
            return 0, total, "approval from someone who is not an owner"
        if identity in done:
            return 0, total, "an owner approved twice"
        chain = resolve(identity)
        if chain is None:
            return 0, total, f"unknown owner identity {identity[:12]}"
        state = a.get("state")
        key = master_key_at(chain, state) if isinstance(state, str) else None
        if key is None:
            return 0, total, "approval names a chain state the owner does not have"
        if a.get("key") != key:
            return 0, total, "approval key is not the owner's key at that state"
        if check_current and key != chain.get_current_master_key():
            return 0, total, "approval uses a key the owner has since replaced"
        try:
            ok = VerifyKey.from_hex(key).verify_hex(approval_message(event, identity, state), a.get("signature", ""))
        except Exception:
            ok = False
        if not ok:
            return 0, total, "owner approval signature invalid"
        done.add(identity)
        approved += weights[identity]
    return approved, total, None


# --- Social recovery ---------------------------------------------------------------------------------------------
#
# A social_recovery event replaces the master key without the old one. It is signed by the NEW key (proof that whoever
# recovers holds it) and carries `recovery_signatures`: trustees named in the identity's latest set_recovery, at least
# `primary_threshold` of them, each signing the identity, the chain head the event follows and the new keys. Like an
# owner approval, a trustee signature names the trustee's chain state and is checked against the trustee's key as of
# that state (so a trustee who recovered their own key can still vouch); a node also demands the trustee's current key.
# Backup trustees are not used yet.


def recovery_message(identity: str, prev: str, new_pubkey: str, new_encryption_pubkey: str, trustee: str, state: str) -> bytes:
    return _canonical({
        "purpose": "nodetide-social-recovery-v1",
        "identity": identity,
        "prev": prev,
        "new_pubkey": new_pubkey,
        "new_encryption_pubkey": new_encryption_pubkey,
        "trustee": trustee,
        "state": state,
    })


def sign_recovery(
    trustee_identity: str, trustee_keypair: KeyPair, trustee_state: str,
    identity: str, prev: str, new_pubkey: str, new_encryption_pubkey: str,
) -> dict[str, str]:
    """A trustee's signature for restoring `identity` (whose chain head is `prev`) to the new keys."""
    return {
        "trustee_identity": trustee_identity,
        "state": trustee_state,
        "key": trustee_keypair.verify_key.to_hex(),
        "signature": trustee_keypair.sign_hex(
            recovery_message(identity, prev, new_pubkey, new_encryption_pubkey, trustee_identity, trustee_state)
        ),
    }


def check_recovery_signature(
    record: Any, identity: str, prev: str, new_pubkey: str, new_encryption_pubkey: str,
    resolve: ChainResolver | None, check_current: bool = False,
) -> str | None:
    """Why one trustee signature does not hold, or None."""
    if not isinstance(record, dict) or not isinstance(record.get("trustee_identity"), str):
        return "a recovery signature names its trustee"
    if resolve is None:
        return "trustee identities are needed to check a recovery"
    trustee, state = record["trustee_identity"], record.get("state")
    chain = resolve(trustee)
    if chain is None:
        return f"unknown trustee {trustee[:12]}"
    key = master_key_at(chain, state) if isinstance(state, str) else None
    if key is None:
        return "recovery signature names a chain state the trustee does not have"
    if record.get("key") != key:
        return "recovery signature key is not the trustee's key at that state"
    if check_current and key != chain.get_current_master_key():
        return "recovery signature uses a key the trustee has since replaced"
    try:
        ok = VerifyKey.from_hex(key).verify_hex(
            recovery_message(identity, prev, new_pubkey, new_encryption_pubkey, trustee, state), record.get("signature", "")
        )
    except Exception:
        ok = False
    return None if ok else "trustee recovery signature invalid"


def check_recovery_event(
    event: SocialRecoveryEvent, identity: str, config: SetRecoveryEvent | None,
    resolve: ChainResolver | None, check_current: bool = False,
) -> str | None:
    """Why a social_recovery event is not backed by enough trustees, or None."""
    if config is None:
        return "no recovery was set up"
    if event.signed_by != event.new_pubkey:
        return "a recovery is signed by the new key"
    done: set[str] = set()
    for record in event.recovery_signatures or []:
        err = check_recovery_signature(
            record, identity, event.prev, event.new_pubkey, event.new_encryption_pubkey, resolve, check_current
        )
        if err:
            return err
        trustee = record["trustee_identity"]
        if trustee not in config.primary_trustees:
            return "recovery signature from someone who is not a trustee"
        if trustee in done:
            return "a trustee signed twice"
        done.add(trustee)
    if len(done) < max(1, config.primary_threshold):
        return f"{len(done)} of {config.primary_threshold} trustees signed"
    return None


def check_recovery_config(event: SetRecoveryEvent, identity: str, resolve: ChainResolver | None) -> str | None:
    """Why a recovery set-up is unusable (so it can never be satisfied or forged), or None."""
    trustees = event.primary_trustees
    if not isinstance(trustees, list) or not all(isinstance(t, str) for t in trustees) or len(set(trustees)) != len(trustees):
        return "trustees are distinct identity hashes"
    if identity in trustees:
        return "you cannot be your own trustee"
    if not isinstance(event.primary_threshold, int) or isinstance(event.primary_threshold, bool) \
            or not 1 <= event.primary_threshold <= len(trustees):
        return "the threshold is between 1 and the number of trustees"
    return None


@dataclass
class Sigchain:
    """Append-only chain of signed events for an identity."""

    events: list[SigchainEvent] = field(default_factory=list)  # the CONTROL chain (linked by prev, genesis first)
    content: list[SigchainEvent] = field(default_factory=list)  # the CONTENT track (add_claim, set_claim_order), by seq
    # Content events a light client was given with a Merkle proof (seq -> event); see attach_content
    sparse: dict[int, SigchainEvent] = field(default_factory=dict)

    @property
    def genesis(self) -> GenesisEvent | None:
        """Get the genesis event."""
        if self.events and isinstance(self.events[0], GenesisEvent):
            return self.events[0]
        return None

    @property
    def identity_hash(self) -> str | None:
        """Get the identity hash (hash of genesis event)."""
        genesis = self.genesis
        if genesis:
            return genesis.event_hash()
        return None

    @property
    def head_hash(self) -> str | None:
        """Get the hash of the latest event."""
        if self.events:
            return self.events[-1].event_hash()
        return None

    def append(self, event: SigchainEvent) -> None:
        """Append an event to its track: content events to the content track, everything else to the control chain."""
        if event.type in CONTENT_TYPES:
            self.content.append(event)
        else:
            self.events.append(event)

    @property
    def content_head(self) -> str | None:
        return self.content[-1].event_hash() if self.content else None

    def content_commitment(self) -> dict[str, Any] | None:
        """What a control event signed now must carry: {count, root} over all content events (None when there are none)."""
        if not self.content:
            return None
        return {"count": len(self.content), "root": merkle_root([e.event_hash() for e in self.content])}

    @property
    def is_partial(self) -> bool:
        """True when the control chain commits to content events this object does not hold (a light chain)."""
        return len(self.content) < self.committed_count()

    def committed_count(self) -> int:
        count = 0
        for event in self.events:
            if event.content is not None and isinstance(event.content.get("count"), int):
                count = max(count, event.content["count"])
        return count

    def all_events(self) -> list[SigchainEvent]:
        """Every event this object holds: the control chain, then the content track (the explorer's event order)."""
        return list(self.events) + list(self.content)

    def to_list(self, light: bool = False) -> list[dict[str, Any]]:
        """Serialize: the control chain, then the content track (omitted when `light`)."""
        out = [e.to_dict() for e in self.events]
        if not light:
            out += [e.to_dict() for e in self.content]
        return out

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_list(), indent=2)

    @classmethod
    def from_list(cls, data: list[dict[str, Any]]) -> Sigchain:
        """Load from list of dicts."""
        events = [SigchainEvent.from_dict(e) for e in data]
        chain = cls()
        for event in events:
            chain.append(event)
        return chain

    @classmethod
    def from_json(cls, json_str: str) -> Sigchain:
        """Load from JSON string."""
        return cls.from_list(json.loads(json_str))

    def get_current_master_key(self) -> str | None:
        """Get the current master public key."""
        if not self.events:
            return None

        master_key = None
        for event in self.events:
            if isinstance(event, GenesisEvent):
                master_key = event.pubkey
            elif isinstance(event, RotateMasterEvent):
                master_key = event.new_pubkey
            elif isinstance(event, SocialRecoveryEvent):
                master_key = event.new_pubkey
        return master_key

    def get_active_devices(self, at_time: int | None = None) -> list[DeviceInfo]:
        """Get list of active device keys."""
        if at_time is None:
            at_time = int(time.time())

        devices: dict[str, DeviceInfo] = {}
        revoked: set[str] = set()

        for event in self.events:
            # Genesis pubkey is the initial device for personal identities
            if isinstance(event, GenesisEvent):
                devices[event.pubkey] = DeviceInfo(
                    pubkey=event.pubkey,
                    encryption_pubkey=event.encryption_pubkey,
                    label="Primary",
                    capabilities=["sign", "encrypt"],
                    added_at=event.timestamp,
                    expires=None,
                )
            elif isinstance(event, AddDeviceEvent):
                # Check if already expired at at_time
                if event.expires and event.expires < at_time:
                    continue
                devices[event.device_pubkey] = DeviceInfo(
                    pubkey=event.device_pubkey,
                    encryption_pubkey=event.device_encryption_pubkey,
                    label=event.label,
                    capabilities=event.capabilities,
                    added_at=event.timestamp,
                    expires=event.expires,
                )
            elif isinstance(event, RevokeDeviceEvent):
                revoked.add(event.device_pubkey)

        # Filter out revoked and expired
        active = []
        for pubkey, info in devices.items():
            if pubkey in revoked:
                continue
            if info.expires and info.expires < at_time:
                continue
            active.append(info)

        return active

    def _content_events(self) -> list[SigchainEvent]:
        """The content events this object can speak about: all of them, or only those a light client was proven."""
        if self.content:
            return list(self.content)
        return [self.sparse[i] for i in sorted(self.sparse)]

    def get_claims(self) -> list[ClaimRecord]:
        """All claims made on this identity, in order, with revocation applied.

        A light chain knows only the claims it was given proofs for; revocations are control events, so it always sees them.
        """
        records: dict[str, ClaimRecord] = {}
        for event in self._content_events():
            if isinstance(event, AddClaimEvent):
                records[event.claim_id] = ClaimRecord(
                    claim_id=event.claim_id,
                    claim_type=event.claim_type,
                    commitment=event.commitment,
                    created_at=event.timestamp,
                    expires=event.expires,
                    event_hash=event.event_hash(),
                    signed_by=event.signed_by,
                )
        for event in self.events:
            if isinstance(event, RevokeClaimEvent) and event.claim_id in records:
                records[event.claim_id].revoked_at = event.timestamp
                records[event.claim_id].revoke_reason = event.reason
        return list(records.values())

    def revoked_claim_ids(self) -> set[str]:
        return {e.claim_id for e in self.events if isinstance(e, RevokeClaimEvent)}

    def get_claim(self, claim_id: str) -> ClaimRecord | None:
        return next((c for c in self.get_claims() if c.claim_id == claim_id), None)

    def claim_order(self, claim_type: str, at_time: int | None = None) -> list[str]:
        """Active claims of one type, the holder's preferred first.

        The newest set_claim_order event for the type decides (ids that have since been revoked or expired drop
        out); active claims it does not list follow in the order they were made.
        """
        active = [c.claim_id for c in self.get_claims() if c.claim_type == claim_type and c.status(at_time) == "active"]
        listed: list[str] = []
        for event in self._content_events():
            if isinstance(event, SetClaimOrderEvent) and event.claim_type == claim_type:
                listed = list(event.order)
        first = [c for c in listed if c in active]
        return first + [c for c in active if c not in first]

    def get_recovery_config(self) -> SetRecoveryEvent | None:
        """Get the current recovery configuration."""
        recovery = None
        for event in self.events:
            if isinstance(event, SetRecoveryEvent):
                recovery = event
        return recovery

    @property
    def is_organization(self) -> bool:
        """True for an identity governed by owners rather than by its own master key (an organization with no
        owners, as every one was before owners existed, is governed by its own key like a personal identity)."""
        genesis = self.genesis
        return genesis is not None and genesis.owners is not None

    def get_owners(self) -> list[dict[str, Any]] | None:
        """The owners in force now ([{identity, weight}]), None for an identity that has none."""
        owners = None
        for event in self.events:
            if isinstance(event, (GenesisEvent, SetOwnersEvent)) and event.owners is not None:
                owners = event.owners
        return owners

    def verify(
        self,
        resolve: ChainResolver | None = None,
        check_current: bool = False,
    ) -> tuple[bool, str | None]:
        """Verify the sigchain.

        An organization identity needs `resolve` (identity hash -> that owner's sigchain) to check its owners'
        approvals. With `check_current`, the newest event's approvals must also use the owners' current keys (what a
        node demands of a new event; older events only need the key the owner had when approving).

        Returns (is_valid, error_message).
        """
        if not self.events:
            return False, "Empty sigchain"

        # First event must be genesis
        if not isinstance(self.events[0], GenesisEvent):
            return False, "First event must be genesis"

        genesis = self.events[0]

        # Verify genesis is self-signed
        genesis_key = VerifyKey.from_hex(genesis.pubkey)
        signable = json.dumps(genesis.signable_dict(), sort_keys=True, separators=(",", ":"))
        if not genesis_key.verify_hex(signable.encode("utf-8"), genesis.signature):
            return False, "Genesis signature invalid"

        owners = genesis.owners
        if owners is not None:
            if genesis.identity_type != IdentityType.ORGANIZATION:
                return False, "Only an organization identity has owners"
            if genesis.governance not in (None, *GOVERNANCE_MODES):
                return False, "Genesis: governance is self or managed"
            err = check_owner_list(owners, resolve)
            if err:
                return False, f"Genesis: {err}"
            # The founding owners all agree to the organization they will own
            approved, total, err = approval_score(genesis, owners, resolve, check_current and len(self.events) == 1)
            if err:
                return False, f"Genesis: {err}"
            if approved != total:
                return False, "Genesis: every founding owner must approve"
        elif genesis.approvals:
            return False, "Genesis: approvals without owners"
        elif genesis.governance is not None:
            return False, "Genesis: governance without owners"

        managed = genesis.governance == "managed"
        governed_types = MANAGED_TYPES if managed else GOVERNED_TYPES

        # Track current master key
        current_master = genesis.pubkey
        prev_hash = genesis.event_hash()
        # Device keys authorized so far: pubkey -> (capabilities, expires); and revoked keys
        devices: dict[str, tuple[list[str], int | None]] = {}
        revoked: set[str] = set()
        revoked_claims: set[str] = set()
        recovery_config: SetRecoveryEvent | None = None

        # Verify each subsequent event
        for i, event in enumerate(self.events[1:], start=1):
            # Check prev hash
            if event.prev != prev_hash:
                return False, f"Event {i}: prev hash mismatch"

            if event.signed_by == GOVERNED:
                # Decided by the owners of an organization, not signed by a key of the chain
                if owners is None:
                    return False, f"Event {i}: only an organization is governed by owners"
                if event.type not in governed_types:
                    return False, f"Event {i}: {event.type.value} cannot be decided by owners"
                if event.signature:
                    return False, f"Event {i}: a governed event has no signature of its own"
                approved, total, err = approval_score(event, owners, resolve, check_current and i == len(self.events) - 1)
                if err:
                    return False, f"Event {i}: {err}"
                if 2 * approved <= total:
                    return False, f"Event {i}: owners approve {approved} of {total}, which is not over half"
                if isinstance(event, AddDeviceEvent):
                    devices[event.device_pubkey] = (list(event.capabilities or []), event.expires)
                elif isinstance(event, RevokeDeviceEvent):
                    revoked.add(event.device_pubkey)
                elif isinstance(event, RotateMasterEvent):
                    current_master = event.new_pubkey
                elif isinstance(event, SetOwnersEvent):
                    err = check_owner_list(event.owners, resolve)
                    if err:
                        return False, f"Event {i}: {err}"
                    owners = event.owners
                prev_hash = event.event_hash()
                continue

            if event.approvals:
                return False, f"Event {i}: approvals belong on governed events only"
            if owners is not None and (
                event.type in (EventType.SET_OWNERS, EventType.SET_RECOVERY, EventType.SOCIAL_RECOVERY)
                or (managed and event.type in MANAGED_TYPES)
            ):
                return False, f"Event {i}: an organization's {event.type.value} is decided by its owners"
            if isinstance(event, SetOwnersEvent):
                return False, f"Event {i}: only an organization has owners"

            if event.type in CONTENT_TYPES or event.seq is not None:
                return False, f"Event {i}: a content event does not belong in the control chain"

            # Get signer key
            signer_key = VerifyKey.from_hex(event.signed_by)

            # Verify signature
            signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
            if not signer_key.verify_hex(signable.encode("utf-8"), event.signature):
                return False, f"Event {i}: signature invalid"

            # Check authorization
            if isinstance(event, (AddDeviceEvent, RevokeDeviceEvent, SetRecoveryEvent, ResolveForkEvent, SetDistributionEvent)):
                # Must be signed by current master
                if event.signed_by != current_master:
                    return False, f"Event {i}: must be signed by master key"
                if isinstance(event, AddDeviceEvent):
                    devices[event.device_pubkey] = (list(event.capabilities or []), event.expires)
                elif isinstance(event, RevokeDeviceEvent):
                    revoked.add(event.device_pubkey)
                elif isinstance(event, SetRecoveryEvent):
                    err = check_recovery_config(event, self.identity_hash, resolve)
                    if err:
                        return False, f"Event {i}: {err}"
                    recovery_config = event
            elif isinstance(event, (RevokeClaimEvent, CheckpointEvent)):
                # Master, or a currently valid device with manage_claims
                if event.signed_by != current_master:
                    caps, expires = devices.get(event.signed_by, ([], None))
                    allowed = (
                        event.signed_by in devices
                        and event.signed_by not in revoked
                        and DeviceCapability.MANAGE_CLAIMS.value in caps
                        and not (expires and expires < event.timestamp)
                    )
                    if not allowed:
                        return False, f"Event {i}: signer may not manage claims"
                if isinstance(event, RevokeClaimEvent):
                    if event.claim_id in revoked_claims:
                        return False, f"Event {i}: claim already revoked"
                    revoked_claims.add(event.claim_id)
            elif isinstance(event, RotateMasterEvent):
                # Must be signed by old master
                if event.signed_by != current_master:
                    return False, f"Event {i}: rotation must be signed by old master"
                current_master = event.new_pubkey
            elif isinstance(event, SocialRecoveryEvent):
                err = check_recovery_event(
                    event, self.identity_hash, recovery_config, resolve, check_current and i == len(self.events) - 1
                )
                if err:
                    return False, f"Event {i}: {err}"
                current_master = event.new_pubkey

            prev_hash = event.event_hash()

        return self._verify_content()

    # --- the two tracks -----------------------------------------------------------------------------------------

    def commitments(self) -> list[tuple[int, str]]:
        """(count, root) in force after each control event: an event without `content` commits what its predecessor did."""
        out: list[tuple[int, str]] = []
        prev = (0, EMPTY_ROOT)
        for event in self.events:
            c = event.content
            if isinstance(c, dict) and isinstance(c.get("count"), int) and isinstance(c.get("root"), str):
                prev = (c["count"], c["root"])
            out.append(prev)
        return out

    def authority_states(self) -> list[tuple[str, dict[str, tuple[list[str], int | None]], set[str]]]:
        """(master key, devices, revoked devices) as of each control event, replayed from the chain."""
        master = self.events[0].pubkey if self.events and isinstance(self.events[0], GenesisEvent) else None
        devices: dict[str, tuple[list[str], int | None]] = {}
        revoked: set[str] = set()
        states = []
        for event in self.events:
            if isinstance(event, AddDeviceEvent):
                devices[event.device_pubkey] = (list(event.capabilities or []), event.expires)
            elif isinstance(event, RevokeDeviceEvent):
                revoked.add(event.device_pubkey)
            elif isinstance(event, (RotateMasterEvent, SocialRecoveryEvent)):
                master = event.new_pubkey
            states.append((master, dict(devices), set(revoked)))
        return states

    @staticmethod
    def _may_manage_claims(state, signer: str, at: int) -> bool:
        master, devices, revoked = state
        if signer == master:
            return True
        caps, expires = devices.get(signer, ([], None))
        return (
            signer in devices and signer not in revoked
            and DeviceCapability.MANAGE_CLAIMS.value in caps
            and not (expires and expires < at)
        )

    def _verify_content(self) -> tuple[bool, str | None]:
        """Commitments of the control chain, and (when this object holds the content) every content event."""
        counts = []
        prev_count = 0
        for i, event in enumerate(self.events):
            c = event.content
            if c is not None:
                if i == 0:
                    return False, "Genesis cannot commit to content"
                if not isinstance(c, dict) or set(c) != {"count", "root"} or isinstance(c["count"], bool) \
                        or not isinstance(c["count"], int) or not isinstance(c["root"], str):
                    return False, f"Event {i}: malformed content commitment"
                if c["count"] < prev_count:
                    return False, f"Event {i}: content commitment goes backwards"
                prev_count = c["count"]
            counts.append(prev_count)
        commitments = self.commitments()
        hashes = [e.event_hash() for e in self.content]
        for i, event in enumerate(self.events):
            count, root = commitments[i]
            if count <= len(hashes) and merkle_root(hashes[:count]) != root:
                return False, f"Event {i}: content commitment does not match the content"

        partial = len(self.content) < counts[-1]
        if partial and not self.content:
            return True, None  # light: the control chain checks out; the content it commits to is not here to check

        index_of = {e.event_hash(): k for k, e in enumerate(self.events)}
        states = self.authority_states()
        last = len(self.events) - 1
        committed_by_ref = [0] * len(self.events)  # content events signed under control event k
        prev_hash: str | None = None
        prev_k = 0
        claims: dict[str, tuple[int, str]] = {}  # claim_id -> (seq, type)
        for i, event in enumerate(self.content):
            tag = f"Content event {i}"
            if event.type not in CONTENT_TYPES or event.seq is None:
                return False, f"{tag}: not a content event"
            if event.seq != i or event.prev != prev_hash:
                return False, f"{tag}: seq or prev does not continue the content track"
            k = index_of.get(event.control_ref)
            if k is None:
                return False, f"{tag}: behind: it names a control event this chain does not have"
            if k < prev_k:
                return False, f"{tag}: control_ref goes backwards"
            if i < commitments[k][0]:
                return False, f"{tag}: already committed before the control event it names"
            if k < last and i >= commitments[k + 1][0]:
                return False, f"{tag}: not committed by the control event that follows its control_ref"
            if not self._may_manage_claims(states[k], event.signed_by, event.timestamp):
                return False, f"{tag}: signer may not manage claims"
            signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
            if not VerifyKey.from_hex(event.signed_by).verify_hex(signable.encode("utf-8"), event.signature):
                return False, f"{tag}: signature invalid"
            committed_by_ref[k] += 1
            if isinstance(event, AddClaimEvent):
                if event.claim_id in claims:
                    return False, f"{tag}: duplicate claim_id"
                claims[event.claim_id] = (i, event.claim_type)
            elif isinstance(event, SetClaimOrderEvent):
                order = event.order
                if not isinstance(order, list) or not 1 <= len(order) <= SetClaimOrderEvent.MAX_ORDER:
                    return False, f"{tag}: a claim order lists between 1 and {SetClaimOrderEvent.MAX_ORDER} claims"
                if len(set(order)) != len(order) or not all(isinstance(c, str) for c in order):
                    return False, f"{tag}: a claim is listed twice"
                revoked_by_k = {
                    e.claim_id for j, e in enumerate(self.events) if j <= k and isinstance(e, RevokeClaimEvent)
                }
                for claim_id in order:
                    if claim_id not in claims:
                        return False, f"{tag}: orders an unknown claim"
                    if claim_id in revoked_by_k:
                        return False, f"{tag}: orders a revoked claim"
                    if claims[claim_id][1] != event.claim_type:
                        return False, f"{tag}: orders a claim of another type"
            prev_hash = event.event_hash()
            prev_k = k

        if partial:
            return True, None  # a chain still being filled: what is here has been checked, the rest is yet to arrive

        # each control event commits exactly the content signed under the control events up to and including its predecessor
        running = 0
        for k in range(len(self.events)):
            if k > 0 and commitments[k][0] != running and self.events[k].content is not None:
                return False, f"Event {k}: commits {commitments[k][0]} content events, {running} exist before it"
            if k > 0 and self.events[k].content is None and running != commitments[k][0]:
                return False, f"Event {k}: content exists that this control event does not commit to"
            running += committed_by_ref[k]

        # a revoked claim must exist, and have been committed no later than the revocation
        for j, event in enumerate(self.events):
            if isinstance(event, RevokeClaimEvent):
                known = claims.get(event.claim_id)
                if known is None:
                    return False, f"Event {j}: revokes an unknown claim"
                if known[0] >= commitments[j][0]:
                    return False, f"Event {j}: revokes a claim its commitment does not cover"
        return True, None

    def attach_content(self, event: SigchainEvent, proof: list[str]) -> str | None:
        """Accept one content event on a light chain, given its Merkle path. Returns why not, or None.

        "behind: ..." means the chain lacks the control event the content names: fetch more control events first.
        """
        if event.type not in CONTENT_TYPES or event.seq is None:
            return "not a content event"
        index_of = {e.event_hash(): k for k, e in enumerate(self.events)}
        k = index_of.get(event.control_ref)
        if k is None:
            return "behind: the content event names a control event this chain does not have"
        if k + 1 >= len(self.events):
            return "not committed yet: no control event after the one it names"
        commitments = self.commitments()
        count_before, (count, root) = commitments[k][0], commitments[k + 1]
        if not count_before <= event.seq < count:
            return "the content event is not in the interval the control chain commits"
        if not verify_proof(event.event_hash(), event.seq, count, proof, root):
            return "the Merkle proof does not match the control chain's commitment"
        if not self._may_manage_claims(self.authority_states()[k], event.signed_by, event.timestamp):
            return "signer may not manage claims"
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        if not VerifyKey.from_hex(event.signed_by).verify_hex(signable.encode("utf-8"), event.signature):
            return "signature invalid"
        self.sparse[event.seq] = event
        return None

    def content_proof(self, seq: int) -> dict[str, Any]:
        """What to send a light client for content event `seq`: the event and its path to the committing control event."""
        if not 0 <= seq < len(self.content):
            raise IndexError("no such content event")
        event = self.content[seq]
        index_of = {e.event_hash(): k for k, e in enumerate(self.events)}
        k = index_of[event.control_ref]
        if k + 1 >= len(self.events):
            raise ValueError("not committed yet")
        count = self.commitments()[k + 1][0]
        return {
            "event": event.to_dict(),
            "proof": merkle_proof([e.event_hash() for e in self.content[:count]], seq),
            "committed_by": self.events[k + 1].event_hash(),
        }


@dataclass
class Identity:
    """A complete identity with sigchain and local keys."""

    sigchain: Sigchain
    local_keypair: KeyPair | None = None  # our key if we control this identity

    @property
    def identity_hash(self) -> str | None:
        """Get the identity hash."""
        return self.sigchain.identity_hash

    @property
    def is_own(self) -> bool:
        """Check if we control this identity."""
        return self.local_keypair is not None

    @classmethod
    def create(
        cls,
        identity_type: IdentityType = IdentityType.PERSONAL,
        name: str | None = None,
        ephemeral: bool = False,
        distribution_points: list[str] | None = None,
    ) -> Identity:
        """Create a new identity."""
        keypair = KeyPair.generate()
        genesis = GenesisEvent.create(
            keypair=keypair,
            identity_type=identity_type,
            name=name,
            ephemeral=ephemeral,
            distribution_points=distribution_points,
        )
        sigchain = Sigchain(events=[genesis])
        return cls(sigchain=sigchain, local_keypair=keypair)

    def add_device(
        self,
        label: str,
        capabilities: list[DeviceCapability] | None = None,
        expires: int | None = None,
    ) -> tuple[KeyPair, AddDeviceEvent]:
        """Add a new device. Returns (device_keypair, event)."""
        if not self.local_keypair:
            raise ValueError("Cannot add device: no local keypair")

        device_keypair = KeyPair.generate()
        event = AddDeviceEvent.create(
            master_keypair=self.local_keypair,
            device_keypair=device_keypair,
            label=label,
            prev_hash=self.sigchain.head_hash,
            capabilities=capabilities,
            expires=expires,
            content=self.sigchain.content_commitment(),
        )
        self.sigchain.append(event)
        return device_keypair, event

    def authorize_device(
        self,
        device_pubkey: str,
        device_encryption_pubkey: str,
        label: str,
        capabilities: list[DeviceCapability] | None = None,
        expires: int | None = None,
    ) -> AddDeviceEvent:
        """Authorize a device that generated its own keys (pairing): only its public keys are needed."""
        if not self.local_keypair:
            raise ValueError("Cannot add device: no local keypair")
        event = AddDeviceEvent.create_for(
            self.local_keypair, device_pubkey, device_encryption_pubkey, label, self.sigchain.head_hash,
            capabilities, expires, self.sigchain.content_commitment(),
        )
        self.sigchain.append(event)
        return event

    def revoke_device(self, device_pubkey: str, reason: str | None = None) -> RevokeDeviceEvent:
        """Revoke a device key."""
        if not self.local_keypair:
            raise ValueError("Cannot revoke device: no local keypair")

        event = RevokeDeviceEvent.create(
            master_keypair=self.local_keypair,
            device_pubkey=device_pubkey,
            prev_hash=self.sigchain.head_hash,
            reason=reason,
            content=self.sigchain.content_commitment(),
        )
        self.sigchain.append(event)
        return event

    def rotate_master(self) -> tuple[KeyPair, RotateMasterEvent]:
        """Rotate the master key. Returns (new_keypair, event)."""
        if not self.local_keypair:
            raise ValueError("Cannot rotate: no local keypair")

        new_keypair = KeyPair.generate()
        event = RotateMasterEvent.create(
            old_keypair=self.local_keypair,
            new_keypair=new_keypair,
            prev_hash=self.sigchain.head_hash,
            content=self.sigchain.content_commitment(),
        )
        self.sigchain.append(event)
        self.local_keypair = new_keypair
        return new_keypair, event

    def set_recovery(
        self,
        primary_trustees: list[str],
        primary_threshold: int,
        backup_trustees: list[str] | None = None,
        backup_threshold: int | None = None,
        backup_activates_after: int | None = None,
    ) -> SetRecoveryEvent:
        """Set recovery trustees."""
        if not self.local_keypair:
            raise ValueError("Cannot set recovery: no local keypair")

        event = SetRecoveryEvent.create(
            master_keypair=self.local_keypair,
            prev_hash=self.sigchain.head_hash,
            primary_trustees=primary_trustees,
            primary_threshold=primary_threshold,
            backup_trustees=backup_trustees,
            backup_threshold=backup_threshold,
            backup_activates_after=backup_activates_after,
            content=self.sigchain.content_commitment(),
        )
        self.sigchain.append(event)
        return event

    def set_distribution_points(self, distribution_points: list[str]) -> SetDistributionEvent:
        """Set or update distribution points."""
        if not self.local_keypair:
            raise ValueError("Cannot set distribution points: no local keypair")

        event = SetDistributionEvent.create(
            master_keypair=self.local_keypair,
            prev_hash=self.sigchain.head_hash,
            distribution_points=distribution_points,
            content=self.sigchain.content_commitment(),
        )
        self.sigchain.append(event)
        return event

    def add_claim(
        self,
        claim_id: str,
        claim_type: str,
        commitment: str,
        signer: KeyPair | SigningKey | None = None,
        expires: int | None = None,
    ) -> AddClaimEvent:
        """Record a claim commitment (signed by the master key unless `signer` is given)."""
        signer = signer or self.local_keypair
        if signer is None:
            raise ValueError("Cannot add claim: no signing key")
        event = AddClaimEvent.create(
            signer, self.sigchain.content_head, claim_id, claim_type, commitment, expires,
            seq=len(self.sigchain.content), control_ref=self.sigchain.head_hash,
        )
        self.sigchain.append(event)
        return event

    def set_claim_order(
        self,
        claim_type: str,
        order: list[str],
        signer: KeyPair | SigningKey | None = None,
    ) -> SetClaimOrderEvent:
        """Say which claims of a type come first (the first is the default)."""
        signer = signer or self.local_keypair
        if signer is None:
            raise ValueError("Cannot order claims: no signing key")
        event = SetClaimOrderEvent.create(
            signer, self.sigchain.content_head, claim_type, order,
            seq=len(self.sigchain.content), control_ref=self.sigchain.head_hash,
        )
        self.sigchain.append(event)
        return event

    def revoke_claim(
        self,
        claim_id: str,
        reason: str | None = None,
        signer: KeyPair | SigningKey | None = None,
    ) -> RevokeClaimEvent:
        """Withdraw a claim."""
        signer = signer or self.local_keypair
        if signer is None:
            raise ValueError("Cannot revoke claim: no signing key")
        event = RevokeClaimEvent.create(
            signer, self.sigchain.head_hash, claim_id, reason, content=self.sigchain.content_commitment()
        )
        self.sigchain.append(event)
        return event

    def checkpoint(self, signer: KeyPair | SigningKey | None = None) -> CheckpointEvent:
        """Commit to the content events so far, so a light verifier can rely on them (see sigchain-v2.md)."""
        signer = signer or self.local_keypair
        if signer is None:
            raise ValueError("Cannot checkpoint: no signing key")
        commitment = self.sigchain.content_commitment()
        if commitment is None:
            raise ValueError("Nothing to commit: there are no content events")
        event = CheckpointEvent.create(signer, self.sigchain.head_hash, commitment)
        self.sigchain.append(event)
        return event

    def verify(self) -> tuple[bool, str | None]:
        """Verify the identity's sigchain."""
        return self.sigchain.verify()
