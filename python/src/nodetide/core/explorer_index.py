"""Rows for the explorer's search index, derived from a sigchain.

The index is a pure function of the stored sigchains (rebuilt whenever one is
saved), so it can always be recreated from scratch.
"""

from __future__ import annotations

import time
from typing import Any

from nodetide.core.identity import (
    AddClaimEvent,
    AddDeviceEvent,
    GenesisEvent,
    ResolveForkEvent,
    RevokeClaimEvent,
    SetClaimOrderEvent,
    RevokeDeviceEvent,
    RotateMasterEvent,
    SetDistributionEvent,
    SetRecoveryEvent,
    Sigchain,
    SigchainEvent,
    SocialRecoveryEvent,
)

MAX_TEXT = 80


def _clip(text: str | None) -> str:
    text = text or ""
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"


def short(key: str) -> str:
    return f"{key[:8]}…{key[-4:]}" if len(key) > 14 else key


def summarize_event(event: SigchainEvent) -> str:
    """One-line human description of an event (plain text, never HTML)."""
    if isinstance(event, GenesisEvent):
        kind = event.identity_type.value
        name = f' "{_clip(event.name)}"' if event.name else ""
        return f"Created {kind} identity{name}"
    if isinstance(event, AddDeviceEvent):
        return f'Added device "{_clip(event.label)}"'
    if isinstance(event, RevokeDeviceEvent):
        reason = f" ({_clip(event.reason)})" if event.reason else ""
        return f"Revoked device {short(event.device_pubkey)}{reason}"
    if isinstance(event, RotateMasterEvent):
        return f"Rotated master key to {short(event.new_pubkey)}"
    if isinstance(event, SetRecoveryEvent):
        n = len(event.primary_trustees)
        return f"Set recovery: {event.primary_threshold} of {n} trustees"
    if isinstance(event, SocialRecoveryEvent):
        return f"Social recovery to master key {short(event.new_pubkey)}"
    if isinstance(event, SetDistributionEvent):
        n = len(event.distribution_points)
        return f"Set {n} distribution point{'s' if n != 1 else ''}"
    if isinstance(event, AddClaimEvent):
        return f"Made a {_clip(event.claim_type)} claim"
    if isinstance(event, RevokeClaimEvent):
        reason = f" ({_clip(event.reason)})" if event.reason else ""
        return f"Revoked claim {short(event.claim_id)}{reason}"
    if isinstance(event, SetClaimOrderEvent):
        return f"Set the order of {len(event.order)} {_clip(event.claim_type)} claim{'s' if len(event.order) != 1 else ''}"
    if isinstance(event, ResolveForkEvent):
        return "Resolved a fork"
    return event.type.value


def event_rows(sigchain: Sigchain) -> list[tuple[Any, ...]]:
    identity = sigchain.identity_hash
    return [
        (
            event.event_hash(),
            identity,
            index,
            event.type.value,
            event.timestamp,
            event.signed_by,
            summarize_event(event),
        )
        for index, event in enumerate(sigchain.all_events())
    ]


def identity_row(sigchain: Sigchain) -> tuple[Any, ...] | None:
    genesis = sigchain.genesis
    if genesis is None or sigchain.identity_hash is None:
        return None
    return (
        sigchain.identity_hash,
        genesis.name,
        genesis.identity_type.value,
        genesis.timestamp,
        sigchain.events[-1].timestamp,
        int(time.time()),
        len(sigchain.all_events()),
        sigchain.head_hash,
        sigchain.get_current_master_key(),
        len(sigchain.get_active_devices()),
    )
