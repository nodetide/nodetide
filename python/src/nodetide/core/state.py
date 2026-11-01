"""A signed snapshot of an identity's *current state*, short enough for a DNS TXT record.

A sigchain can be long; to check "may this device act for this identity right now" only the present state matters:
the master key, the active devices, the head. A state document carries exactly that, vouched for by the master key,
plus the proof that this master key belongs to the identity: the genesis event (whose hash IS the identity) and every
master rotation since, each signed by the key before it. See state-record.md.

    {"body": {...current state...}, "sig": <master key over the body>, "lineage": [genesis, rotate_master, ...]}

What a state cannot do that a chain can: show *history* (claims, who was revoked when), and prove nothing newer exists.
Freshness is bounded by `exp` in the body, and anything that matters beyond authentication (claims, attestations)
still needs the chain.

Supported: personal identities whose master key changed only by rotate_master. Organizations (owner-governed rotation)
and identities that used social recovery or fork resolution need other chains to be verified, so they are refused
(StateError) rather than half-supported: use the sigchain for those.
"""

from __future__ import annotations

import base64
import json
import time
import zlib
from dataclasses import dataclass
from typing import Any

from nodetide.core.crypto import KeyPair, VerifyKey
from nodetide.core.identity import (
    DeviceInfo,
    EventType,
    GenesisEvent,
    RotateMasterEvent,
    Sigchain,
    SigchainEvent,
)

STATE_VERSION = 1
PREFIX = "nt1;"                         # the TXT value starts with this
DOMAIN = b"nodetide-state-v1\x00"       # the signature cannot be replayed as anything else
MAX_TEXT = 3800                         # characters of the TXT value; a DNS answer over TCP stays comfortably below 4 KB
MAX_RAW = 16 * 1024                     # decompressed size we accept
MAX_DEVICES = 12
MAX_LINEAGE = 8                         # master rotations we follow (longer: use the chain)
DEFAULT_VALIDITY = 7 * 24 * 3600
CLOCK_SKEW = 300


class StateError(Exception):
    """The state cannot be made, or does not verify."""


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_input(body: dict[str, Any]) -> bytes:
    return DOMAIN + _canonical(body)


def _event_signature_ok(event: SigchainEvent) -> bool:
    try:
        signable = json.dumps(event.signable_dict(), sort_keys=True, separators=(",", ":"))
        return VerifyKey.from_hex(event.signed_by).verify_hex(signable.encode("utf-8"), event.signature)
    except Exception:
        return False


@dataclass
class VerifiedState:
    """What a state document proved. Looks enough like a Sigchain for assertion checks (verify_assertion_with_state)."""

    identity_hash: str
    head_hash: str
    length: int                     # control events in the chain when the state was made
    master: str
    master_encryption: str
    devices: list[DeviceInfo]
    content: dict[str, Any] | None
    timestamp: int
    expires: int
    lineage_length: int

    def get_current_master_key(self) -> str:
        return self.master

    def get_active_devices(self, at_time: int | None = None) -> list[DeviceInfo]:
        now = int(time.time()) if at_time is None else at_time
        return [d for d in self.devices if not d.expires or d.expires >= now]


# --- making a state -----------------------------------------------------------------------------------------------

def build_state(chain: Sigchain, master: KeyPair, now: int | None = None, validity: int = DEFAULT_VALIDITY) -> dict[str, Any]:
    """The state document for `chain`, signed by `master` (which must be the chain's current master key)."""
    now = int(time.time()) if now is None else now
    ok, error = chain.verify()
    if not ok:
        raise StateError(f"the sigchain does not verify: {error}")
    genesis = chain.genesis
    if genesis is None or genesis.owners is not None:
        raise StateError("organizations cannot publish a state (their master key is governed by their owners): use the sigchain")
    lineage: list[SigchainEvent] = [genesis]
    for event in chain.events[1:]:
        if event.type == EventType.ROTATE_MASTER:
            if not isinstance(event, RotateMasterEvent) or event.signed_by == "owners":
                raise StateError("a governed master rotation cannot be followed from a state: use the sigchain")
            lineage.append(event)
        elif event.type in (EventType.SOCIAL_RECOVERY, EventType.RESOLVE_FORK, EventType.SET_OWNERS):
            raise StateError(f"this identity used {event.type.value}, which a state cannot prove: use the sigchain")
    if len(lineage) > MAX_LINEAGE:
        raise StateError("too many master rotations for a short record: use the sigchain")
    current = chain.get_current_master_key()
    if master.verify_key.to_hex() != current:
        raise StateError("this is not the identity's current master key")
    devices = [d for d in chain.get_active_devices(now) if d.pubkey != current]
    if len(devices) > MAX_DEVICES:
        raise StateError(f"{len(devices)} devices do not fit a short record (the limit is {MAX_DEVICES}): revoke unused ones")
    body = {
        "v": STATE_VERSION,
        "id": chain.identity_hash,
        "head": chain.head_hash,
        "n": len(chain.events),
        "master": {"sign": current, "enc": _master_encryption(chain, lineage)},
        "devices": [
            {"k": d.pubkey, "e": d.encryption_pubkey, "c": sorted(d.capabilities), "a": d.added_at, "x": d.expires}
            for d in devices
        ],
        "content": chain.content_commitment(),
        "ts": now,
        "exp": now + validity,
    }
    return {
        "body": body,
        "sig": master.sign_hex(_sign_input(body)),
        "lineage": [e.to_dict() for e in lineage],
    }


def _master_encryption(chain: Sigchain, lineage: list[SigchainEvent]) -> str:
    last = lineage[-1]
    return last.new_encryption_pubkey if isinstance(last, RotateMasterEvent) else last.encryption_pubkey  # type: ignore[union-attr]


# --- text form (what goes into DNS) -------------------------------------------------------------------------------

def encode(doc: dict[str, Any]) -> str:
    """`nt1;` + base64url(deflate(canonical JSON)). Raises StateError when it would not fit a TXT record."""
    text = PREFIX + base64.urlsafe_b64encode(zlib.compress(_canonical(doc), 9)).decode("ascii").rstrip("=")
    if len(text) > MAX_TEXT:
        raise StateError(f"the state is {len(text)} characters, more than a TXT record should carry ({MAX_TEXT}): use the sigchain")
    return text


def decode(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or not text.startswith(PREFIX) or len(text) > MAX_TEXT:
        raise StateError("not a state record")
    payload = text[len(PREFIX):]
    try:
        packed = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        inflater = zlib.decompressobj()
        raw = inflater.decompress(packed, MAX_RAW + 1)
        if len(raw) > MAX_RAW or inflater.unconsumed_tail:
            raise StateError("the state record expands to too much")
        doc = json.loads(raw)
    except StateError:
        raise
    except Exception as e:
        raise StateError("the state record is damaged") from e
    if not isinstance(doc, dict):
        raise StateError("the state record is not an object")
    return doc


def txt_strings(text: str) -> list[str]:
    """The value as DNS character-strings of at most 255 bytes, to be quoted in a zone file."""
    return [text[i:i + 255] for i in range(0, len(text), 255)]


# --- checking a state ---------------------------------------------------------------------------------------------

def verify_state(doc: Any, expect_identity: str | None = None, now: int | None = None, max_age: int | None = None) -> VerifiedState:
    """Check a state document. Raises StateError. `max_age` (seconds) demands a recent snapshot, for sensitive uses."""
    now = int(time.time()) if now is None else now
    if not isinstance(doc, dict) or not isinstance(doc.get("body"), dict) or not isinstance(doc.get("lineage"), list):
        raise StateError("malformed state")
    body, sig, lineage = doc["body"], doc.get("sig"), doc["lineage"]
    if body.get("v") != STATE_VERSION:
        raise StateError("unsupported state version")
    if not isinstance(sig, str) or not 1 <= len(lineage) <= MAX_LINEAGE:
        raise StateError("malformed state")

    # the lineage: genesis (its hash is the identity), then rotate_master events, each signed by the key before
    try:
        events = [SigchainEvent.from_dict(e) for e in lineage]
    except Exception as e:
        raise StateError("malformed lineage") from e
    genesis = events[0]
    if not isinstance(genesis, GenesisEvent) or genesis.owners is not None or genesis.signed_by != genesis.pubkey:
        raise StateError("the lineage does not start with a personal genesis")
    if not _event_signature_ok(genesis):
        raise StateError("the genesis signature is wrong")
    identity = genesis.event_hash()
    if body.get("id") != identity or (expect_identity is not None and expect_identity != identity):
        raise StateError("the state belongs to another identity")
    master, master_enc, last_ts = genesis.pubkey, genesis.encryption_pubkey, genesis.timestamp
    for event in events[1:]:
        if not isinstance(event, RotateMasterEvent) or event.signed_by != master or event.timestamp < last_ts:
            raise StateError("the lineage is not a chain of master rotations")
        if not _event_signature_ok(event):
            raise StateError("a rotation signature is wrong")
        master, master_enc, last_ts = event.new_pubkey, event.new_encryption_pubkey, event.timestamp

    # the snapshot, vouched for by the master key the lineage ends in
    m = body.get("master")
    if not isinstance(m, dict) or m.get("sign") != master or m.get("enc") != master_enc:
        raise StateError("the state names a master key the lineage does not lead to")
    try:
        sig_ok = VerifyKey.from_hex(master).verify_hex(_sign_input(body), sig)
    except Exception:
        sig_ok = False
    if not sig_ok:
        raise StateError("the state signature is wrong")

    ts, exp = body.get("ts"), body.get("exp")
    head, n = body.get("head"), body.get("n")
    if any(isinstance(v, bool) or not isinstance(v, int) for v in (ts, exp, n)) or not isinstance(head, str) or n < 1:
        raise StateError("malformed state")
    if ts > now + CLOCK_SKEW:
        raise StateError("the state is dated in the future")
    if exp < now - CLOCK_SKEW:
        raise StateError("the state has expired: republish it")
    if max_age is not None and now - ts > max_age:
        raise StateError("the state is older than this use allows")

    devices = []
    raw_devices = body.get("devices")
    if not isinstance(raw_devices, list) or len(raw_devices) > MAX_DEVICES:
        raise StateError("malformed device list")
    for d in raw_devices:
        try:
            caps, added, expires = d["c"], d["a"], d.get("x")
            if not (isinstance(d["k"], str) and isinstance(d["e"], str) and isinstance(caps, list) and all(isinstance(c, str) for c in caps)
                    and isinstance(added, int) and (expires is None or isinstance(expires, int))):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise StateError("malformed device entry") from None
        devices.append(DeviceInfo(pubkey=d["k"], encryption_pubkey=d["e"], label="", capabilities=caps, added_at=added, expires=expires))
    content = body.get("content")
    if content is not None and not isinstance(content, dict):
        raise StateError("malformed content commitment")
    return VerifiedState(identity, head, n, master, master_enc, devices, content, ts, exp, len(events))
