"""API route handlers."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from aiohttp import web

logger = logging.getLogger(__name__)

from nodetide.core.identity import (
    Sigchain,
    SigchainEvent,
    GenesisEvent,
    SocialRecoveryEvent,
    check_recovery_signature,
)
from nodetide.core.storage import Storage
from nodetide.core.trust import TrustGraph, TrustDelegation
from nodetide.api.claims import setup_claims_routes
from nodetide.api.pairing import setup_pairing_routes
from nodetide.api.models import (
    APIError,
    ErrorCode,
    CreateIdentityResponse,
    IdentityResponse,
    SubmitEventResponse,
    SigchainResponse,
    SessionResponse,
    RecoveryStatusResponse,
    TrustCalculationResponse,
    VerifyResponse,
)
from nodetide.api.auth import (
    SessionStore,
    RecoveryStore,
    verify_event_signature,
    verify_session_request,
    extract_bearer_token,
    setup_native_auth_routes,
)


def error_response(error: ErrorCode, message: str, status: int, details: dict | None = None) -> web.Response:
    """Create an error response."""
    return web.json_response(
        APIError(error=error.value, message=message, code=status, details=details).to_dict(),
        status=status,
    )


# Identity routes

async def create_identity(request: web.Request) -> web.Response:
    """POST /identities - Create identity with genesis event."""
    storage: Storage = request.app["storage"]

    try:
        data = await request.json()
        event_data = data.get("event")
        if not event_data:
            logger.warning("create_identity: Missing event")
            return error_response(ErrorCode.INVALID_REQUEST, "Missing event", 400)

        if event_data.get("type") != "genesis":
            logger.warning(f"create_identity: Expected genesis, got {event_data.get('type')}")
            return error_response(ErrorCode.INVALID_REQUEST, "Expected genesis event", 400)

        # Verify self-signature
        logger.info("create_identity: verifying signature...")
        valid, err = verify_event_signature(event_data)
        if not valid:
            logger.warning(f"create_identity: signature verification failed: {err}")
            return error_response(ErrorCode.INVALID_SIGNATURE, err or "Invalid signature", 400)

        # Parse event
        logger.info("create_identity: parsing event...")
        event = SigchainEvent.from_dict(event_data)  # keeps an organization's owner approvals

        # Create sigchain
        sigchain = Sigchain(events=[event])
        identity_hash = sigchain.identity_hash
        logger.info(f"create_identity: identity_hash={identity_hash}")

        # Verify sigchain
        logger.info("create_identity: verifying sigchain...")
        already_known = storage.get_sigchain(identity_hash) is not None
        valid, err = sigchain.verify(storage.get_sigchain, check_current=not already_known)
        if not valid:
            logger.warning(f"create_identity: sigchain verification failed: {err}")
            return error_response(ErrorCode.INVALID_SIGCHAIN, err or "Invalid sigchain", 400)

        # A genesis event is public, so posting it again must never replace what the identity has become since
        # (devices, claims, recovery): answer "already there" and leave the stored chain alone.
        if already_known:
            return web.json_response(
                CreateIdentityResponse(
                    identity_hash=identity_hash,
                    accepted=True,
                    event_hash=event.event_hash(),
                ).to_dict(),
                status=200,
            )

        # Save
        storage.save_sigchain(sigchain)

        return web.json_response(
            CreateIdentityResponse(
                identity_hash=identity_hash,
                accepted=True,
                event_hash=event.event_hash(),
            ).to_dict(),
            status=201,
        )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)
    except Exception as e:
        return error_response(ErrorCode.INVALID_REQUEST, str(e), 400)


async def list_identities(request: web.Request) -> web.Response:
    """GET /identities - List known identities."""
    storage: Storage = request.app["storage"]

    # Get all sigchains (local and remote)
    all_ids = storage.list_all_sigchains()
    local_ids = set(storage.list_local_identities())

    identities = []
    for identity_hash in all_ids:
        sigchain = storage.get_sigchain(identity_hash)
        if sigchain and sigchain.genesis:
            identities.append({
                "identity_hash": identity_hash,
                "name": sigchain.genesis.name,
                "type": sigchain.genesis.identity_type.value,
                "is_local": identity_hash in local_ids,
            })

    return web.json_response({"identities": identities})


async def get_identity(request: web.Request) -> web.Response:
    """GET /identities/{hash} - Get identity details."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    genesis = sigchain.genesis
    if not genesis:
        return error_response(ErrorCode.INVALID_SIGCHAIN, "Invalid sigchain - no genesis", 400)

    # Check if local
    local_ids = storage.list_local_identities()
    is_local = identity_hash in local_ids

    # Get devices
    devices = []
    for device in sigchain.get_active_devices():
        devices.append({
            "pubkey": device.pubkey,
            "encryption_pubkey": device.encryption_pubkey,
            "label": device.label,
            "capabilities": device.capabilities,
            "added_at": device.added_at,
            "expires": device.expires,
        })

    # Get recovery config
    recovery_event = sigchain.get_recovery_config()
    recovery = None
    if recovery_event:
        recovery = {
            "primary_trustees": recovery_event.primary_trustees,
            "primary_threshold": recovery_event.primary_threshold,
            "backup_trustees": recovery_event.backup_trustees,
            "backup_threshold": recovery_event.backup_threshold,
        }

    # Verify
    valid, _ = sigchain.verify(storage.get_sigchain)

    return web.json_response(
        IdentityResponse(
            identity_hash=identity_hash,
            name=genesis.name,
            identity_type=genesis.identity_type.value,
            created_at=genesis.timestamp,
            is_local=is_local,
            devices=devices,
            recovery=recovery,
            sigchain_length=len(sigchain.events),
            sigchain=sigchain.to_list(),
            verified=valid,
            master_pubkey=sigchain.get_current_master_key() or "",
        ).to_dict()
    )


async def get_sigchain(request: web.Request) -> web.Response:
    """GET /identities/{hash}/sigchain - Get full sigchain."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    return web.json_response(
        SigchainResponse(
            identity_hash=identity_hash,
            head_hash=sigchain.head_hash or "",
            length=len(sigchain.events),
            events=sigchain.to_list(),
        ).to_dict()
    )


async def submit_event(request: web.Request) -> web.Response:
    """POST /identities/{hash}/events - Submit a signed event."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    try:
        data = await request.json()
        event_data = data.get("event")

        if not event_data:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing event", 400)

        # Check prev hash
        if event_data.get("prev") != sigchain.head_hash:
            return error_response(
                ErrorCode.STALE_STATE,
                "prev hash mismatch - client has stale state",
                409,
                details={
                    "expected_prev": sigchain.head_hash,
                    "received_prev": event_data.get("prev"),
                },
            )

        # Verify signature
        valid, err = verify_event_signature(event_data, sigchain)
        if not valid:
            return error_response(ErrorCode.INVALID_SIGNATURE, err or "Invalid signature", 400)

        # Parse and append event
        event = SigchainEvent.from_dict(event_data)
        sigchain.append(event)

        # Verify updated sigchain (an organization's owner approvals are checked against the owners' chains here)
        valid, err = sigchain.verify(storage.get_sigchain, check_current=True)
        if not valid:
            return error_response(ErrorCode.INVALID_SIGCHAIN, err or "Invalid sigchain after append", 400)

        if isinstance(event, SocialRecoveryEvent):
            recovery_store = request.app["recovery_store"]
            for pending in recovery_store.get_for_identity(identity_hash):
                recovery_store.delete(pending.recovery_id)

        # Handle device key storage if requested
        if data.get("store_device_key") and data.get("device_private_key_encrypted"):
            # TODO: Store encrypted device key
            pass

        # Save
        storage.save_sigchain(sigchain)

        return web.json_response(
            SubmitEventResponse(
                accepted=True,
                event_hash=event.event_hash(),
                sigchain_length=len(sigchain.events),
            ).to_dict(),
            status=201,
        )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)
    except Exception as e:
        return error_response(ErrorCode.INVALID_REQUEST, str(e), 400)


async def list_devices(request: web.Request) -> web.Response:
    """GET /identities/{hash}/devices - List devices."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    devices = []
    for device in sigchain.get_active_devices():
        devices.append({
            "pubkey": device.pubkey,
            "encryption_pubkey": device.encryption_pubkey,
            "label": device.label,
            "capabilities": device.capabilities,
            "added_at": device.added_at,
            "expires": device.expires,
        })

    return web.json_response({"devices": devices})


# Session routes

async def create_session(request: web.Request) -> web.Response:
    """POST /session - Create a session."""
    storage: Storage = request.app["storage"]
    session_store: SessionStore = request.app["session_store"]

    try:
        data = await request.json()

        identity = data.get("identity")
        device_pubkey = data.get("device_pubkey")
        expires_in = data.get("expires_in", 3600)

        if not identity or not device_pubkey:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing identity or device_pubkey", 400)

        # Get sigchain
        sigchain = storage.get_sigchain(identity)
        if not sigchain:
            return error_response(ErrorCode.NOT_FOUND, f"Identity {identity} not found", 404)

        # Verify request signature
        valid, err = verify_session_request(data, sigchain)
        if not valid:
            return error_response(ErrorCode.INVALID_SIGNATURE, err or "Invalid signature", 401)

        # Create session
        session = session_store.create(
            identity=identity,
            device_pubkey=device_pubkey,
            expires_in=expires_in,
        )

        return web.json_response(
            SessionResponse(
                token=session.token,
                expires_at=session.expires_at,
                identity=session.identity,
            ).to_dict(),
            status=201,
        )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)


async def get_session(request: web.Request) -> web.Response:
    """GET /session - Check session status."""
    session_store: SessionStore = request.app["session_store"]

    token = extract_bearer_token(request.headers.get("Authorization"))
    if not token:
        return error_response(ErrorCode.UNAUTHORIZED, "Missing or invalid token", 401)

    session = session_store.get(token)
    if not session:
        return error_response(ErrorCode.UNAUTHORIZED, "Invalid or expired session", 401)

    return web.json_response({
        "identity": session.identity,
        "device_pubkey": session.device_pubkey,
        "expires_at": session.expires_at,
        "created_at": session.created_at,
    })


async def delete_session(request: web.Request) -> web.Response:
    """DELETE /session - Invalidate session."""
    session_store: SessionStore = request.app["session_store"]

    token = extract_bearer_token(request.headers.get("Authorization"))
    if not token:
        return error_response(ErrorCode.UNAUTHORIZED, "Missing token", 401)

    if session_store.delete(token):
        return web.json_response({"deleted": True})
    else:
        return error_response(ErrorCode.NOT_FOUND, "Session not found", 404)


# Recovery routes

async def initiate_recovery(request: web.Request) -> web.Response:
    """POST /identities/{hash}/recovery/initiate - Start recovery."""
    storage: Storage = request.app["storage"]
    recovery_store: RecoveryStore = request.app["recovery_store"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)
    if not sigchain:
        return error_response(ErrorCode.NOT_FOUND, f"Identity {identity_hash} not found", 404)

    recovery_config = sigchain.get_recovery_config()
    if not recovery_config:
        return error_response(ErrorCode.INVALID_REQUEST, "No recovery config set", 400)

    try:
        data = await request.json()

        new_pubkey = data.get("new_pubkey")
        new_encryption_pubkey = data.get("new_encryption_pubkey")
        initiated_by = data.get("initiated_by")

        if not new_pubkey or not new_encryption_pubkey:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing new keys", 400)

        # Verify initiator is a trustee
        all_trustees = recovery_config.primary_trustees + (recovery_config.backup_trustees or [])
        if initiated_by and initiated_by not in all_trustees:
            return error_response(ErrorCode.FORBIDDEN, "Initiator not a trustee", 403)

        if len(recovery_store.get_for_identity(identity_hash)) >= 5:
            return error_response(ErrorCode.INVALID_REQUEST, "Too many pending recoveries for this identity", 429)

        # Create pending recovery
        recovery = recovery_store.create(
            prev=sigchain.head_hash,
            identity=identity_hash,
            new_pubkey=new_pubkey,
            new_encryption_pubkey=new_encryption_pubkey,
            initiated_by=initiated_by or "unknown",
            threshold=recovery_config.primary_threshold,
            trustees=recovery_config.primary_trustees,
        )

        return web.json_response(
            RecoveryStatusResponse(
                recovery_id=recovery.recovery_id,
                identity=identity_hash,
                status="pending",
                threshold=recovery.threshold,
                collected=0,
                signatures=[],
                expires_at=recovery.expires_at,
                prev=recovery.prev,
            ).to_dict(),
            status=201,
        )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)


async def submit_recovery_signature(request: web.Request) -> web.Response:
    """POST /identities/{hash}/recovery/{id}/sign - Submit a trustee's signature.

    The node checks it against the trustee's chain and keeps it. Once enough trustees have signed, the status is
    "complete" and carries the signature records; the recovering client builds the social_recovery event, signs it with
    the new key and submits it like any other event (the node checks the trustees again then).
    """
    storage: Storage = request.app["storage"]
    recovery_store: RecoveryStore = request.app["recovery_store"]
    identity_hash = request.match_info["hash"]
    recovery_id = request.match_info["id"]

    recovery = recovery_store.get(recovery_id)
    if not recovery:
        return error_response(ErrorCode.NOT_FOUND, "Recovery not found or expired", 404)

    if recovery.identity != identity_hash:
        return error_response(ErrorCode.NOT_FOUND, "Recovery not for this identity", 404)

    try:
        data = await request.json()
    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)

    record = data.get("record") if isinstance(data.get("record"), dict) else data
    trustee_identity = record.get("trustee_identity")
    signature = record.get("signature")
    if not trustee_identity or not signature:
        return error_response(ErrorCode.INVALID_REQUEST, "Missing trustee_identity or signature", 400)

    if trustee_identity not in recovery.trustees:
        return error_response(ErrorCode.FORBIDDEN, "Not a trustee for this identity", 403)

    sigchain = storage.get_sigchain(identity_hash)
    if sigchain is None or sigchain.head_hash != recovery.prev:
        return error_response(ErrorCode.STALE_STATE, "The identity changed since this recovery was started", 409)

    err = check_recovery_signature(
        record, identity_hash, recovery.prev, recovery.new_pubkey, recovery.new_encryption_pubkey,
        storage.get_sigchain, check_current=True,
    )
    if err:
        return error_response(ErrorCode.INVALID_SIGNATURE, err, 400)

    recovery = recovery_store.add_signature(
        recovery_id, trustee_identity, signature,
        {k: record[k] for k in ("trustee_identity", "state", "key", "signature")},
    )
    if not recovery:
        return error_response(ErrorCode.INVALID_REQUEST, "Failed to add signature", 400)

    return web.json_response(_recovery_status(recovery))


def _recovery_status(recovery) -> dict:
    return RecoveryStatusResponse(
        recovery_id=recovery.recovery_id,
        identity=recovery.identity,
        status="complete" if recovery.is_complete else "pending",
        threshold=recovery.threshold,
        collected=recovery.collected,
        signatures=[
            {"trustee": t, "signed_at": s["signed_at"], "record": s.get("record")}
            for t, s in recovery.signatures.items()
        ],
        expires_at=recovery.expires_at,
        prev=recovery.prev,
        new_master_pubkey=recovery.new_pubkey,
        new_encryption_pubkey=recovery.new_encryption_pubkey,
    ).to_dict()


async def get_recovery_status(request: web.Request) -> web.Response:
    """GET /identities/{hash}/recovery/{id} - Check recovery status."""
    recovery_store: RecoveryStore = request.app["recovery_store"]
    identity_hash = request.match_info["hash"]
    recovery_id = request.match_info["id"]

    recovery = recovery_store.get(recovery_id)
    if not recovery:
        return error_response(ErrorCode.NOT_FOUND, "Recovery not found or expired", 404)

    if recovery.identity != identity_hash:
        return error_response(ErrorCode.NOT_FOUND, "Recovery not for this identity", 404)

    return web.json_response(_recovery_status(recovery))


async def list_pending_recoveries(request: web.Request) -> web.Response:
    """GET /identities/{hash}/recovery/pending - List pending recoveries."""
    recovery_store: RecoveryStore = request.app["recovery_store"]
    identity_hash = request.match_info["hash"]

    recoveries = recovery_store.get_for_identity(identity_hash)

    return web.json_response({
        "recoveries": [
            {
                "recovery_id": r.recovery_id,
                "status": "pending",
                "threshold": r.threshold,
                "collected": r.collected,
                "expires_at": r.expires_at,
                "new_pubkey": r.new_pubkey,
                "prev": r.prev,
            }
            for r in recoveries
        ]
    })


# Trust routes

async def create_delegation(request: web.Request) -> web.Response:
    """POST /trust/delegations - Create trust delegation."""
    storage: Storage = request.app["storage"]
    session_store: SessionStore = request.app["session_store"]

    # Check auth
    token = extract_bearer_token(request.headers.get("Authorization"))
    if not token:
        return error_response(ErrorCode.UNAUTHORIZED, "Missing authorization", 401)

    session = session_store.get(token)
    if not session:
        return error_response(ErrorCode.UNAUTHORIZED, "Invalid session", 401)

    try:
        data = await request.json()
        delegation_data = data.get("delegation")

        if not isinstance(delegation_data, dict):
            return error_response(ErrorCode.INVALID_REQUEST, "Missing delegation", 400)

        # Delegation must be from the session identity
        if delegation_data.get("from_identity") != session.identity:
            return error_response(ErrorCode.FORBIDDEN, "Can only create delegations from your identity", 403)

        try:
            delegation = TrustDelegation.from_dict({
                **delegation_data,
                "timestamp": delegation_data.get("timestamp", int(time.time())),
            })
        except (KeyError, TypeError, ValueError) as e:
            return error_response(ErrorCode.INVALID_REQUEST, f"Invalid delegation: {e}", 400)

        storage.save_trust_delegation(
            from_identity=delegation.from_identity,
            to_identity=delegation.to_identity,
            weight=delegation.weight,
            timestamp=delegation.timestamp,
            depth_limit=delegation.depth_limit,
            scope=delegation.scope,
        )

        return web.json_response({
            "accepted": True,
            "from": delegation.from_identity,
            "to": delegation.to_identity,
        }, status=201)

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)


async def list_delegations(request: web.Request) -> web.Response:
    """GET /trust/delegations - Query delegations."""
    storage: Storage = request.app["storage"]

    from_identity = request.query.get("from")
    if not from_identity:
        return error_response(ErrorCode.INVALID_REQUEST, "Missing 'from' parameter", 400)

    delegations = storage.get_trust_delegations(from_identity)

    return web.json_response({"delegations": delegations})


async def calculate_trust(request: web.Request) -> web.Response:
    """GET /trust/calculate/{hash}?claim_type=&max_depth= - trust in an attestation issuer."""
    storage: Storage = request.app["storage"]
    session_store: SessionStore = request.app["session_store"]

    subject = request.match_info["hash"]
    claim_type = request.query.get("claim_type") or None
    try:
        max_depth = max(1, min(int(request.query.get("max_depth", "3")), 6))
    except ValueError:
        return error_response(ErrorCode.INVALID_REQUEST, "max_depth must be an integer", 400)

    # Need a session to know whose perspective to use
    token = extract_bearer_token(request.headers.get("Authorization"))
    if not token:
        return error_response(ErrorCode.UNAUTHORIZED, "Session required for trust calculation", 401)

    session = session_store.get(token)
    if not session:
        return error_response(ErrorCode.UNAUTHORIZED, "Invalid session", 401)

    # Load the delegations reachable from this identity, breadth first
    graph = TrustGraph(my_identity=session.identity)
    frontier, seen = [session.identity], {session.identity}
    for _ in range(max_depth):
        next_frontier: list[str] = []
        for identity in frontier:
            for d in storage.get_trust_delegations(identity):
                graph.add_delegation(TrustDelegation.from_dict(d))
                if d["to_identity"] not in seen:
                    seen.add(d["to_identity"])
                    next_frontier.append(d["to_identity"])
        frontier = next_frontier

    result = graph.calculate_trust(subject, claim_type, max_depth)

    return web.json_response(
        TrustCalculationResponse(
            subject=result.subject,
            claim_type=result.claim_type,
            trust_score=result.trust_score,
            paths=[
                {"hops": p.hops, "weights": p.weights, "combined_score": p.combined_score}
                for p in result.paths
            ],
        ).to_dict()
    )


# Query routes

async def verify_sigchain(request: web.Request) -> web.Response:
    """POST /verify - Verify a sigchain."""
    try:
        data = await request.json()
        events_data = data.get("sigchain")

        if not events_data:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing sigchain", 400)

        sigchain = Sigchain.from_list(events_data)
        valid, err = sigchain.verify(request.app["storage"].get_sigchain)

        if valid:
            return web.json_response(
                VerifyResponse(
                    valid=True,
                    identity_hash=sigchain.identity_hash,
                    events=len(sigchain.events),
                    current_master=sigchain.get_current_master_key(),
                    active_devices=len(sigchain.get_active_devices()),
                ).to_dict()
            )
        else:
            return web.json_response(
                VerifyResponse(valid=False, error=err).to_dict(),
                status=400,
            )

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)
    except Exception as e:
        return web.json_response(
            VerifyResponse(valid=False, error=str(e)).to_dict(),
            status=400,
        )


async def lookup_identity(request: web.Request) -> web.Response:
    """GET /lookup/{hash} - Lookup identity."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    sigchain = storage.get_sigchain(identity_hash)

    if sigchain:
        genesis = sigchain.genesis
        return web.json_response({
            "found": True,
            "identity_hash": identity_hash,
            "name": genesis.name if genesis else None,
            "type": genesis.identity_type.value if genesis else None,
            "sigchain_length": len(sigchain.events),
        })
    else:
        return web.json_response({
            "found": False,
            "identity_hash": identity_hash,
        })


# ============================================
# MESSAGE ROUTES
# ============================================

async def publish_message(request: web.Request) -> web.Response:
    """POST /messages - Publish a signed public message."""
    storage: Storage = request.app["storage"]

    try:
        data = await request.json()
        message_data = data.get("message")
        if not message_data:
            return error_response(ErrorCode.INVALID_REQUEST, "Missing message", 400)

        # Validate required fields
        required = ["type", "sender", "content", "created_at", "signature"]
        for field in required:
            if field not in message_data:
                return error_response(ErrorCode.INVALID_REQUEST, f"Missing field: {field}", 400)

        if message_data.get("type") != "public":
            return error_response(ErrorCode.INVALID_REQUEST, "Only public messages supported", 400)

        # Verify sender exists
        sender = message_data["sender"]
        sigchain = storage.get_sigchain(sender)
        if not sigchain:
            return error_response(ErrorCode.NOT_FOUND, f"Sender {sender} not found", 404)

        # Verify signature against any active device key
        from nodetide.messaging.message import PublicMessage
        msg = PublicMessage.from_dict(message_data)
        signable = json.dumps(msg.signable_dict(), sort_keys=True, separators=(",", ":"))

        active_devices = sigchain.get_active_devices()
        if not active_devices:
            return error_response(ErrorCode.INVALID_SIGCHAIN, "No active devices for sender", 400)

        from nodetide.core.crypto import VerifyKey
        signature_valid = False
        for device in active_devices:
            try:
                pubkey = VerifyKey.from_hex(device.pubkey)
                if pubkey.verify_hex(signable.encode(), msg.signature):
                    signature_valid = True
                    break
            except Exception:
                continue

        if not signature_valid:
            logger.warning(f"[publish_message] Signature verification failed for sender {sender}")
            return error_response(ErrorCode.INVALID_SIGNATURE, "Invalid message signature", 400)

        # Save message
        message_hash = msg.message_hash
        storage.save_message(
            message_hash=message_hash,
            bundle_json=json.dumps(message_data),
            sender_identity=sender,
            recipient_identity=None,
            message_type="public",
            created_at=message_data["created_at"],
        )

        return web.json_response({
            "message_hash": message_hash,
            "accepted": True,
        }, status=201)

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)
    except Exception as e:
        logger.exception("Error publishing message")
        return error_response(ErrorCode.INTERNAL_ERROR, str(e), 500)


async def list_messages(request: web.Request) -> web.Response:
    """GET /messages - List public messages."""
    storage: Storage = request.app["storage"]

    sender = request.query.get("sender")
    limit = int(request.query.get("limit", 50))

    messages = storage.list_messages(
        sender_identity=sender,
        message_type="public",
        limit=limit,
    )

    return web.json_response({
        "messages": [json.loads(m["bundle_json"]) for m in messages],
    })


async def get_message(request: web.Request) -> web.Response:
    """GET /messages/{hash} - Get a specific message."""
    storage: Storage = request.app["storage"]
    message_hash = request.match_info["hash"]

    message = storage.get_message(message_hash)
    if not message:
        return error_response(ErrorCode.NOT_FOUND, "Message not found", 404)

    return web.json_response({
        "message": json.loads(message["bundle_json"]),
        "message_hash": message_hash,
    })


# Relay routes (only active in relay mode)


async def relay_status(request: web.Request) -> web.Response:
    """GET /relay/status - Get relay status."""
    poller = request.app.get("relay_poller")
    if not poller:
        return error_response(ErrorCode.NOT_FOUND, "Relay mode not enabled", 404)

    return web.json_response(poller.get_status())


async def relay_add_identity(request: web.Request) -> web.Response:
    """POST /relay/identities - Add identity to relay."""
    storage: Storage = request.app["storage"]
    poller = request.app.get("relay_poller")

    try:
        data = await request.json()
        identity_hash = data.get("identity_hash")
        distribution_points = data.get("distribution_points", [])

        if not identity_hash:
            return error_response(ErrorCode.INVALID_REQUEST, "identity_hash required", 400)

        # If no distribution points provided, try to fetch from existing sigchain
        if not distribution_points:
            sigchain = storage.get_sigchain(identity_hash)
            if sigchain:
                for event in sigchain.events:
                    if hasattr(event, 'distribution_points') and event.distribution_points:
                        distribution_points = event.distribution_points

        storage.add_relayed_identity(identity_hash, distribution_points)

        # Trigger immediate poll if poller is active
        if poller and poller.is_running and not poller.is_suspended:
            poller.trigger_poll()

        return web.json_response({
            "identity_hash": identity_hash,
            "distribution_points": distribution_points,
            "added": True,
        }, status=201)

    except json.JSONDecodeError:
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid JSON", 400)


async def relay_remove_identity(request: web.Request) -> web.Response:
    """DELETE /relay/identities/{hash} - Remove identity from relay."""
    storage: Storage = request.app["storage"]
    identity_hash = request.match_info["hash"]

    removed = storage.remove_relayed_identity(identity_hash)

    if removed:
        return web.json_response({"removed": True})
    else:
        return error_response(ErrorCode.NOT_FOUND, "Identity not in relay", 404)


async def relay_list_identities(request: web.Request) -> web.Response:
    """GET /relay/identities - List relayed identities."""
    storage: Storage = request.app["storage"]

    identities = storage.list_relayed_identities()

    return web.json_response({"identities": identities})


async def relay_suspend(request: web.Request) -> web.Response:
    """POST /relay/polling/suspend - Suspend polling."""
    poller = request.app.get("relay_poller")
    if not poller:
        return error_response(ErrorCode.NOT_FOUND, "Relay mode not enabled", 404)

    poller.suspend()
    return web.json_response({"suspended": True})


async def relay_resume(request: web.Request) -> web.Response:
    """POST /relay/polling/resume - Resume polling."""
    poller = request.app.get("relay_poller")
    if not poller:
        return error_response(ErrorCode.NOT_FOUND, "Relay mode not enabled", 404)

    poller.resume()
    return web.json_response({"suspended": False})


async def relay_poll_now(request: web.Request) -> web.Response:
    """POST /relay/polling/trigger - Trigger immediate poll."""
    poller = request.app.get("relay_poller")
    if not poller:
        return error_response(ErrorCode.NOT_FOUND, "Relay mode not enabled", 404)

    poller.trigger_poll()
    return web.json_response({"triggered": True})


async def relay_set_interval(request: web.Request) -> web.Response:
    """PUT /relay/polling/interval - Set polling interval."""
    poller = request.app.get("relay_poller")
    if not poller:
        return error_response(ErrorCode.NOT_FOUND, "Relay mode not enabled", 404)

    try:
        data = await request.json()
        interval = int(data.get("interval", 300))

        if interval < 30:
            return error_response(ErrorCode.INVALID_REQUEST, "Interval must be at least 30 seconds", 400)

        poller.set_interval(interval)
        return web.json_response({"interval": interval})

    except (json.JSONDecodeError, ValueError):
        return error_response(ErrorCode.INVALID_REQUEST, "Invalid interval", 400)


async def relay_discover(request: web.Request) -> web.Response:
    """GET /relay/discover - Discover relay nodes on local network via mDNS.

    Query params:
        timeout: Discovery timeout in seconds (default 3, max 10)
    """
    import asyncio
    from nodetide.relay import RelayDiscovery

    timeout = min(int(request.query.get("timeout", 3)), 10)
    relays_found = []

    def on_found(ip: str, port: int, props: dict):
        relays_found.append({
            "ip": ip,
            "port": port,
            "url": f"http://{ip}:{port}",
            "properties": props,
        })

    discovery = RelayDiscovery(on_found=on_found)
    await discovery.start()
    await asyncio.sleep(timeout)
    await discovery.stop()

    return web.json_response({
        "relays": relays_found,
        "timeout": timeout,
    })


def setup_routes(app: web.Application) -> None:
    """Setup all API routes."""

    # Identity routes
    app.router.add_post("/api/identities", create_identity)
    app.router.add_get("/api/identities", list_identities)
    app.router.add_get("/api/identities/{hash}", get_identity)
    app.router.add_get("/api/identities/{hash}/sigchain", get_sigchain)
    app.router.add_post("/api/identities/{hash}/events", submit_event)
    app.router.add_get("/api/identities/{hash}/devices", list_devices)

    # Session routes
    app.router.add_post("/api/session", create_session)
    app.router.add_get("/api/session", get_session)
    app.router.add_delete("/api/session", delete_session)

    # Native SSO routes (challenge / verify / login)
    setup_native_auth_routes(app)

    # Claims and attestations
    setup_claims_routes(app)

    # Device pairing rendezvous
    setup_pairing_routes(app)

    # Recovery routes
    app.router.add_post("/api/identities/{hash}/recovery/initiate", initiate_recovery)
    app.router.add_post("/api/identities/{hash}/recovery/{id}/sign", submit_recovery_signature)
    app.router.add_get("/api/identities/{hash}/recovery/{id}", get_recovery_status)
    app.router.add_get("/api/identities/{hash}/recovery/pending", list_pending_recoveries)

    # Trust routes
    app.router.add_post("/api/trust/delegations", create_delegation)
    app.router.add_get("/api/trust/delegations", list_delegations)
    app.router.add_get("/api/trust/calculate/{hash}", calculate_trust)

    # Query routes
    app.router.add_post("/api/verify", verify_sigchain)
    app.router.add_get("/api/lookup/{hash}", lookup_identity)

    # Message routes
    app.router.add_post("/api/messages", publish_message)
    app.router.add_get("/api/messages", list_messages)
    app.router.add_get("/api/messages/{hash}", get_message)

    # Relay routes (work in any mode, but poller only in relay mode)
    app.router.add_get("/api/relay/status", relay_status)
    app.router.add_get("/api/relay/discover", relay_discover)
    app.router.add_post("/api/relay/identities", relay_add_identity)
    app.router.add_get("/api/relay/identities", relay_list_identities)
    app.router.add_delete("/api/relay/identities/{hash}", relay_remove_identity)
    app.router.add_post("/api/relay/polling/suspend", relay_suspend)
    app.router.add_post("/api/relay/polling/resume", relay_resume)
    app.router.add_post("/api/relay/polling/trigger", relay_poll_now)
    app.router.add_put("/api/relay/polling/interval", relay_set_interval)
