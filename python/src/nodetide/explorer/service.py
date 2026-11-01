"""Read-only queries behind the explorer.

Only information a node already publishes is exposed here: sigchains and their
events, public (signed, unencrypted) messages, trust delegations,
and relay subscriptions. Never exposed: private keys, sessions, pending
recoveries, challenges, or non-public messages.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from nodetide.core.crypto import VerifyKey
from nodetide.core.explorer_index import summarize_event
from nodetide.core.identity import (
    AddDeviceEvent,
    GenesisEvent,
    RevokeDeviceEvent,
    RotateMasterEvent,
    SetDistributionEvent,
    Sigchain,
    SocialRecoveryEvent,
)
from nodetide.core.storage import Storage

MAX_LIMIT = 100
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_PREFIX_RE = re.compile(r"^[0-9a-f]{4,64}$")
PREVIEW_CHARS = 280

IDENTITY_SORTS = {
    "recent": "last_event_at DESC, identity_hash",
    "created": "created_at DESC, identity_hash",
    "events": "event_count DESC, last_event_at DESC, identity_hash",
    "name": "name COLLATE NOCASE ASC, created_at DESC, identity_hash",
}


def is_hash(value: str) -> bool:
    return bool(HASH_RE.match(value))


def like_escape(text: str) -> str:
    """Escape LIKE wildcards (use with ESCAPE '\\')."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def clip(text: str, limit: int = PREVIEW_CHARS) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Explorer:
    def __init__(self, storage: Storage):
        self.storage = storage

    # --- helpers -------------------------------------------------------------

    def _all(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self.storage.transaction() as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]

    def _one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        rows = self._all(sql, params)
        return rows[0] if rows else None

    def _count(self, sql: str, params: tuple | list = ()) -> int:
        row = self._one(sql, params)
        return int(next(iter(row.values()))) if row else 0

    @staticmethod
    def _page(items: list[dict], total: int, limit: int, offset: int) -> dict[str, Any]:
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    # --- overview ------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        span = self._one("SELECT MIN(timestamp) AS first, MAX(timestamp) AS last FROM explorer_events")
        types = self._all(
            "SELECT event_type, COUNT(*) AS n FROM explorer_events GROUP BY event_type ORDER BY n DESC"
        )
        latest_msg = self._one("SELECT MAX(created_at) AS t FROM messages WHERE message_type = 'public'")
        return {
            "identities": self._count("SELECT COUNT(*) FROM explorer_identities"),
            "events": self._count("SELECT COUNT(*) FROM explorer_events"),
            "public_messages": self._count(
                "SELECT COUNT(*) FROM messages WHERE message_type = 'public'"
            ),
            "trust_delegations": self._count("SELECT COUNT(*) FROM trust_delegations"),
            "attestations": self._count("SELECT COUNT(*) FROM attestations"),
            "relayed_identities": self._count("SELECT COUNT(*) FROM relayed_identities"),
            "event_types": {row["event_type"]: row["n"] for row in types},
            "first_event_at": span["first"] if span else None,
            "last_event_at": span["last"] if span else None,
            "last_message_at": latest_msg["t"] if latest_msg else None,
            "generated_at": int(time.time()),
        }

    # --- identities ----------------------------------------------------------

    def list_identities(
        self, limit: int = 25, offset: int = 0, q: str | None = None, sort: str = "recent"
    ) -> dict[str, Any]:
        order = IDENTITY_SORTS.get(sort, IDENTITY_SORTS["recent"])
        where, params = "1=1", []
        if q and q.strip():
            needle = q.strip()  # names keep their casing (LIKE only folds ASCII)
            where = "(name LIKE ? ESCAPE '\\' OR identity_hash LIKE ? ESCAPE '\\')"
            params = [f"%{like_escape(needle)}%", f"{like_escape(needle.lower())}%"]
        total = self._count(f"SELECT COUNT(*) FROM explorer_identities WHERE {where}", params)
        items = self._all(
            f"""
            SELECT identity_hash, name, identity_type, created_at, last_event_at,
                   event_count, device_count, head_hash, master_pubkey
            FROM explorer_identities WHERE {where}
            ORDER BY {order} LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        return self._page(items, total, limit, offset)

    def _name_of(self, identity_hash: str | None) -> str | None:
        if not identity_hash:
            return None
        row = self._one("SELECT name FROM explorer_identities WHERE identity_hash = ?", [identity_hash])
        return row["name"] if row else None

    def get_identity(self, identity_hash: str) -> dict[str, Any] | None:
        chain = self.storage.get_sigchain(identity_hash)
        genesis = chain.genesis if chain else None
        if chain is None or genesis is None:
            return None

        valid, error = chain.verify(self.storage.get_sigchain)
        now = int(time.time())

        distribution_points: list[str] = []
        master_history: list[dict[str, Any]] = []
        for index, event in enumerate(chain.events):
            if isinstance(event, GenesisEvent):
                master_history.append(
                    {"pubkey": event.pubkey, "since": event.timestamp, "via": "genesis",
                     "event_hash": event.event_hash()}
                )
                distribution_points = event.distribution_points or distribution_points
            elif isinstance(event, RotateMasterEvent):
                master_history.append(
                    {"pubkey": event.new_pubkey, "since": event.timestamp, "via": "rotate_master",
                     "event_hash": event.event_hash()}
                )
            elif isinstance(event, SocialRecoveryEvent):
                master_history.append(
                    {"pubkey": event.new_pubkey, "since": event.timestamp, "via": "social_recovery",
                     "event_hash": event.event_hash()}
                )
            elif isinstance(event, SetDistributionEvent):
                distribution_points = event.distribution_points

        recovery = chain.get_recovery_config()
        relay = self.storage.get_relayed_identity(identity_hash)

        return {
            "identity_hash": identity_hash,
            "name": genesis.name,
            "identity_type": genesis.identity_type.value,
            "ephemeral": genesis.ephemeral,
            "created_at": genesis.timestamp,
            "last_event_at": chain.events[-1].timestamp,
            "verified": valid,
            "verify_error": error,
            "head_hash": chain.head_hash,
            "event_count": len(chain.events),
            "master_pubkey": chain.get_current_master_key(),
            "encryption_pubkey": genesis.encryption_pubkey,
            "master_history": master_history,
            "devices": self._device_history(chain, now),
            "distribution_points": distribution_points,
            "claims": self._claims(identity_hash, chain, now),
            "recovery": None if recovery is None else {
                "primary_trustees": [
                    {"identity_hash": t, "name": self._name_of(t)} for t in recovery.primary_trustees
                ],
                "primary_threshold": recovery.primary_threshold,
                "backup_trustees": [
                    {"identity_hash": t, "name": self._name_of(t)}
                    for t in (recovery.backup_trustees or [])
                ],
                "backup_threshold": recovery.backup_threshold,
                "backup_activates_after": recovery.backup_activates_after,
                "event_hash": recovery.event_hash(),
            },
            "events": [
                {
                    "index": index,
                    "event_hash": event.event_hash(),
                    "type": event.type.value,
                    "timestamp": event.timestamp,
                    "signed_by": event.signed_by,
                    "summary": summarize_event(event),
                }
                for index, event in enumerate(chain.events)
            ],
            "counts": {
                "public_messages": self._count(
                    "SELECT COUNT(*) FROM messages WHERE message_type = 'public' AND sender_identity = ?",
                    [identity_hash],
                ),
                "delegations_from": self._count(
                    "SELECT COUNT(*) FROM trust_delegations WHERE from_identity = ?", [identity_hash]
                ),
                "delegations_to": self._count(
                    "SELECT COUNT(*) FROM trust_delegations WHERE to_identity = ?", [identity_hash]
                ),
                "attestations_about": self._count("SELECT COUNT(*) FROM attestations WHERE subject = ?", [identity_hash]),
                "attestations_issued": self._count("SELECT COUNT(*) FROM attestations WHERE issuer = ?", [identity_hash]),
            },
            "relay": relay,
        }

    def _claims(self, identity_hash: str, chain: Sigchain, now: int) -> list[dict[str, Any]]:
        """Claims on the chain. A value is shown only if the holder published the document."""
        documents = self.storage.get_claim_documents(identity_hash)
        attestations = self.list_attestations(limit=100, offset=0, subject=identity_hash)["items"]
        result = []
        for record in chain.get_claims():
            document = documents.get(record.claim_id)
            result.append({
                "claim_id": record.claim_id,
                "claim_type": record.claim_type,
                "status": record.status(now),
                "commitment": record.commitment,
                "created_at": record.created_at,
                "expires": record.expires,
                "revoked_at": record.revoked_at,
                "revoke_reason": record.revoke_reason,
                "event_hash": record.event_hash,
                "published": document is not None,
                "value": document["value"] if document else None,
                "attestations": [a for a in attestations if a["claim_id"] == record.claim_id],
            })
        return result

    def list_attestations(
        self,
        limit: int = 25,
        offset: int = 0,
        subject: str | None = None,
        issuer: str | None = None,
        claim_type: str | None = None,
    ) -> dict[str, Any]:
        where, params = ["1=1"], []
        for column, value in (("a.subject", subject), ("a.issuer", issuer), ("a.claim_type", claim_type)):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        clause = " AND ".join(where)
        now = int(time.time())
        total = self._count(f"SELECT COUNT(*) FROM attestations a WHERE {clause}", params)
        items = self._all(
            f"""
            SELECT a.attestation_id, a.subject, subj.name AS subject_name, a.claim_id, a.claim_type,
                   a.issuer, iss.name AS issuer_name, a.method, a.assurance, a.issued_at, a.expires_at,
                   r.issued_at AS revoked_at, r.reason AS revoke_reason
            FROM attestations a
            LEFT JOIN explorer_identities subj ON subj.identity_hash = a.subject
            LEFT JOIN explorer_identities iss ON iss.identity_hash = a.issuer
            LEFT JOIN attestation_revocations r ON r.attestation_id = a.attestation_id
            WHERE {clause}
            ORDER BY a.issued_at DESC, a.attestation_id LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        for item in items:
            item["expired"] = now > item["expires_at"]
            item["revoked"] = item["revoked_at"] is not None
        return self._page(items, total, limit, offset)

    @staticmethod
    def _device_history(chain: Sigchain, now: int) -> list[dict[str, Any]]:
        """Every device key the identity ever authorized, with its current status."""
        devices: dict[str, dict[str, Any]] = {}
        for event in chain.events:
            if isinstance(event, GenesisEvent):
                devices[event.pubkey] = {
                    "pubkey": event.pubkey, "label": "Genesis key", "role": "genesis",
                    "capabilities": ["sign", "encrypt"], "added_at": event.timestamp,
                    "expires": None, "revoked_at": None, "revoke_reason": None,
                    "event_hash": event.event_hash(),
                }
            elif isinstance(event, AddDeviceEvent):
                devices[event.device_pubkey] = {
                    "pubkey": event.device_pubkey, "label": event.label, "role": "device",
                    "capabilities": list(event.capabilities), "added_at": event.timestamp,
                    "expires": event.expires, "revoked_at": None, "revoke_reason": None,
                    "event_hash": event.event_hash(),
                }
            elif isinstance(event, RevokeDeviceEvent) and event.device_pubkey in devices:
                devices[event.device_pubkey]["revoked_at"] = event.timestamp
                devices[event.device_pubkey]["revoke_reason"] = event.reason

        master = chain.get_current_master_key()
        result = []
        for info in devices.values():
            if info["revoked_at"] is not None:
                info["status"] = "revoked"
            elif info["expires"] and info["expires"] < now:
                info["status"] = "expired"
            else:
                info["status"] = "active"
            info["is_master"] = info["pubkey"] == master
            result.append(info)
        return result

    # --- events ----------------------------------------------------------------

    def list_events(
        self,
        limit: int = 25,
        offset: int = 0,
        event_type: str | None = None,
        identity: str | None = None,
    ) -> dict[str, Any]:
        where, params = ["1=1"], []
        if event_type:
            where.append("e.event_type = ?")
            params.append(event_type)
        if identity:
            where.append("e.identity_hash = ?")
            params.append(identity)
        clause = " AND ".join(where)
        total = self._count(f"SELECT COUNT(*) FROM explorer_events e WHERE {clause}", params)
        items = self._all(
            f"""
            SELECT e.event_hash, e.identity_hash, i.name AS identity_name, e.idx AS "index",
                   e.event_type AS type, e.timestamp, e.signed_by, e.summary
            FROM explorer_events e
            LEFT JOIN explorer_identities i ON i.identity_hash = e.identity_hash
            WHERE {clause}
            ORDER BY e.timestamp DESC, e.idx DESC, e.event_hash
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        return self._page(items, total, limit, offset)

    def get_event(self, event_hash: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT identity_hash, idx FROM explorer_events WHERE event_hash = ?", [event_hash]
        )
        if row is None:
            return None
        chain = self.storage.get_sigchain(row["identity_hash"])
        if chain is None or row["idx"] >= len(chain.events):
            return None
        index = row["idx"]
        event = chain.events[index]
        return {
            "event_hash": event_hash,
            "identity_hash": row["identity_hash"],
            "identity_name": self._name_of(row["identity_hash"]),
            "index": index,
            "chain_length": len(chain.events),
            "type": event.type.value,
            "timestamp": event.timestamp,
            "signed_by": event.signed_by,
            "summary": summarize_event(event),
            "prev_hash": chain.events[index - 1].event_hash() if index > 0 else None,
            "next_hash": chain.events[index + 1].event_hash() if index + 1 < len(chain.events) else None,
            "raw": event.to_dict(),
        }

    # --- public messages -----------------------------------------------------------

    @staticmethod
    def _content_view(bundle: dict[str, Any]) -> tuple[str, str | None]:
        """(text preview, content type) for a public message's content."""
        content = bundle.get("content")
        content_type = None
        if isinstance(content, dict):
            ctype = content.get("content_type")
            content_type = ctype if isinstance(ctype, str) else None
            body = content.get("body")
            if isinstance(body, str):
                return body, content_type
        if isinstance(content, str):
            return content, content_type
        return json.dumps(content, sort_keys=True, ensure_ascii=False), content_type

    def _message_summary(self, row: dict[str, Any]) -> dict[str, Any]:
        try:
            bundle = json.loads(row["bundle_json"])
        except (TypeError, ValueError):
            bundle = {}
        text, content_type = self._content_view(bundle if isinstance(bundle, dict) else {})
        return {
            "message_hash": row["message_hash"],
            "sender": row["sender_identity"],
            "sender_name": row.get("sender_name"),
            "created_at": row["created_at"],
            "received_at": row["received_at"],
            "preview": clip(text),
            "truncated": len(text) > PREVIEW_CHARS,
            "content_type": content_type,
            "reply_to": bundle.get("reply_to") if isinstance(bundle, dict) else None,
        }

    def list_messages(
        self, limit: int = 25, offset: int = 0, sender: str | None = None
    ) -> dict[str, Any]:
        where, params = ["m.message_type = 'public'"], []
        if sender:
            where.append("m.sender_identity = ?")
            params.append(sender)
        clause = " AND ".join(where)
        total = self._count(f"SELECT COUNT(*) FROM messages m WHERE {clause}", params)
        rows = self._all(
            f"""
            SELECT m.message_hash, m.sender_identity, m.created_at, m.received_at,
                   m.bundle_json, i.name AS sender_name
            FROM messages m
            LEFT JOIN explorer_identities i ON i.identity_hash = m.sender_identity
            WHERE {clause}
            ORDER BY m.created_at DESC, m.message_hash
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        return self._page([self._message_summary(r) for r in rows], total, limit, offset)

    def get_message(self, message_hash: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT m.message_hash, m.sender_identity, m.created_at, m.received_at,
                   m.bundle_json, i.name AS sender_name
            FROM messages m
            LEFT JOIN explorer_identities i ON i.identity_hash = m.sender_identity
            WHERE m.message_hash = ? AND m.message_type = 'public'
            """,
            [message_hash],
        )
        if row is None:
            return None
        try:
            bundle = json.loads(row["bundle_json"])
        except (TypeError, ValueError):
            bundle = {}
        if not isinstance(bundle, dict):
            bundle = {}
        text, content_type = self._content_view(bundle)
        view = self._message_summary(row)
        view.update({
            "text": text,
            "preview": view["preview"],
            "content_type": content_type,
            "signature_status": self._verify_message(bundle),
            "raw": bundle,
        })
        return view

    def _verify_message(self, bundle: dict[str, Any]) -> str:
        """valid | invalid | unknown_sender | malformed.

        "invalid" means no key the sender currently has (active device keys or
        master key) produced the signature. Messages fetched from other nodes are
        not verified when stored, so this is the place to check them.
        """
        from nodetide.messaging.message import PublicMessage

        sender = bundle.get("sender")
        chain = self.storage.get_sigchain(sender) if isinstance(sender, str) else None
        if chain is None:
            return "unknown_sender"
        try:
            message = PublicMessage.from_dict(bundle)
            signable = json.dumps(
                message.signable_dict(), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            signature = message.signature
        except Exception:
            return "malformed"
        keys = {d.pubkey for d in chain.get_active_devices()}
        master = chain.get_current_master_key()
        if master:
            keys.add(master)
        for key in keys:
            try:
                if VerifyKey.from_hex(key).verify_hex(signable, signature):
                    return "valid"
            except Exception:
                continue
        return "invalid"

    # --- trust ------------------------------------------------------------------

    def list_delegations(
        self,
        limit: int = 25,
        offset: int = 0,
        from_identity: str | None = None,
        to_identity: str | None = None,
    ) -> dict[str, Any]:
        where, params = ["1=1"], []
        if from_identity:
            where.append("d.from_identity = ?")
            params.append(from_identity)
        if to_identity:
            where.append("d.to_identity = ?")
            params.append(to_identity)
        clause = " AND ".join(where)
        total = self._count(f"SELECT COUNT(*) FROM trust_delegations d WHERE {clause}", params)
        items = self._all(
            f"""
            SELECT d.from_identity AS "from", s1.name AS from_name,
                   d.to_identity AS "to", s2.name AS to_name,
                   d.weight, d.depth_limit, d.timestamp, d.scope
            FROM trust_delegations d
            LEFT JOIN explorer_identities s1 ON s1.identity_hash = d.from_identity
            LEFT JOIN explorer_identities s2 ON s2.identity_hash = d.to_identity
            WHERE {clause}
            ORDER BY d.timestamp DESC, d.id DESC LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        for item in items:
            item["scope"] = json.loads(item["scope"]) if item.get("scope") else None
        return self._page(items, total, limit, offset)

    # --- search -------------------------------------------------------------------

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Find identities, events and messages by (prefix of) hash, or identities by name."""
        name_query = query.strip()
        q = name_query.lower()
        if not q:
            return []
        results: list[dict[str, Any]] = []

        if HEX_PREFIX_RE.match(q):
            like = f"{q}%"  # hex only, so no wildcard characters can sneak in
            for row in self._all(
                "SELECT identity_hash, name FROM explorer_identities WHERE identity_hash LIKE ? LIMIT ?",
                [like, limit],
            ):
                results.append({"kind": "identity", "id": row["identity_hash"], "label": row["name"]})
            for row in self._all(
                "SELECT event_hash, summary FROM explorer_events WHERE event_hash LIKE ? LIMIT ?",
                [like, limit],
            ):
                results.append({"kind": "event", "id": row["event_hash"], "label": row["summary"]})
            for row in self._all(
                "SELECT message_hash FROM messages WHERE message_type = 'public' "
                "AND message_hash LIKE ? LIMIT ?",
                [like, limit],
            ):
                results.append({"kind": "message", "id": row["message_hash"], "label": None})

        for row in self._all(
            "SELECT identity_hash, name FROM explorer_identities "
            "WHERE name LIKE ? ESCAPE '\\' ORDER BY last_event_at DESC LIMIT ?",
            [f"%{like_escape(name_query)}%", limit],
        ):
            if not any(r["kind"] == "identity" and r["id"] == row["identity_hash"] for r in results):
                results.append({"kind": "identity", "id": row["identity_hash"], "label": row["name"]})
        return results[: limit * 3]

    # --- network ----------------------------------------------------------------------

    def network(self, poller_status: dict[str, Any] | None = None) -> dict[str, Any]:
        relayed = self.storage.list_relayed_identities()
        items = []
        for entry in relayed:
            identity = entry["identity_hash"]
            items.append({
                "identity_hash": identity,
                "name": self._name_of(identity),
                "known": self._one(
                    "SELECT 1 AS x FROM explorer_identities WHERE identity_hash = ?", [identity]
                ) is not None,
                "distribution_points": entry.get("distribution_points") or [],
                "added_at": entry.get("added_at"),
                "last_polled_at": entry.get("last_polled_at"),
                "last_poll_success": entry.get("last_poll_success"),
                "poll_error": entry.get("poll_error"),
            })
        polling = None
        if poller_status is not None:
            polling = {
                "running": poller_status.get("running"),
                "suspended": poller_status.get("suspended"),
                "poll_interval": poller_status.get("poll_interval"),
            }
        return {"mode": "relay" if poller_status is not None else "standard",
                "polling": polling, "relayed": items}
