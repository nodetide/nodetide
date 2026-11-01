"""Local storage using SQLite.

Stores identities, sigchains, keys, messages, and content.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from nodetide.core.crypto import KeyPair
from nodetide.core.identity import Identity, Sigchain


SCHEMA_VERSION = 1

SCHEMA = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

-- Local identities (ones we control)
CREATE TABLE IF NOT EXISTS local_identities (
    identity_hash TEXT PRIMARY KEY,
    signing_key TEXT NOT NULL,
    encryption_key TEXT NOT NULL,
    is_default INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- All known sigchains (local and remote)
CREATE TABLE IF NOT EXISTS sigchains (
    identity_hash TEXT PRIMARY KEY,
    sigchain_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Trust delegations
CREATE TABLE IF NOT EXISTS trust_delegations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_identity TEXT NOT NULL,
    to_identity TEXT NOT NULL,
    weight REAL NOT NULL,
    depth_limit INTEGER,
    timestamp INTEGER NOT NULL,
    scope TEXT,  -- JSON list of claim types, NULL = all
    UNIQUE(from_identity, to_identity)
);

-- Messages (received and sent)
CREATE TABLE IF NOT EXISTS messages (
    message_hash TEXT PRIMARY KEY,
    bundle_json TEXT NOT NULL,
    sender_identity TEXT NOT NULL,
    recipient_identity TEXT,
    message_type TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    received_at INTEGER,
    read_at INTEGER,
    status TEXT DEFAULT 'pending'
);

-- Content chunks
CREATE TABLE IF NOT EXISTS content_chunks (
    chunk_hash TEXT PRIMARY KEY,
    manifest_hash TEXT,
    chunk_index INTEGER,
    data BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

-- Content manifests
CREATE TABLE IF NOT EXISTS content_manifests (
    manifest_hash TEXT PRIMARY KEY,
    manifest_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    total_size INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

-- Relay warnings (unreliable relays)
CREATE TABLE IF NOT EXISTS relay_warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    relay_node TEXT NOT NULL,
    reporter_identity TEXT NOT NULL,
    issue TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence TEXT,
    timestamp INTEGER NOT NULL,
    signature TEXT NOT NULL
);

-- Routing hints
CREATE TABLE IF NOT EXISTS routing_hints (
    identity_hash TEXT NOT NULL,
    node_identity TEXT NOT NULL,
    cla_type TEXT NOT NULL,
    address TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    confidence REAL DEFAULT 1.0,
    PRIMARY KEY (identity_hash, node_identity)
);

-- Groups
CREATE TABLE IF NOT EXISTS groups (
    group_id TEXT PRIMARY KEY,
    group_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Relayed identities (for relay mode)
CREATE TABLE IF NOT EXISTS relayed_identities (
    identity_hash TEXT PRIMARY KEY,
    distribution_points TEXT,  -- JSON array of distribution point URLs
    added_at INTEGER NOT NULL,
    last_polled_at INTEGER,
    last_poll_success INTEGER,
    poll_error TEXT
);

-- Relay configuration
CREATE TABLE IF NOT EXISTS relay_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Claim documents the holder chose to publish (value + salt are public once here)
CREATE TABLE IF NOT EXISTS claim_documents (
    identity_hash TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    claim_type TEXT NOT NULL,
    value_json TEXT NOT NULL,
    salt TEXT NOT NULL,
    published_at INTEGER NOT NULL,
    PRIMARY KEY (identity_hash, claim_id)
);

-- Attestations (signed statements that a claim was verified)
CREATE TABLE IF NOT EXISTS attestations (
    attestation_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    claim_type TEXT NOT NULL,
    commitment TEXT NOT NULL,
    issuer TEXT,
    method TEXT NOT NULL,
    assurance TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    body_json TEXT NOT NULL,
    received_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attestation_revocations (
    attestation_id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    reason TEXT,
    issued_at INTEGER NOT NULL,
    body_json TEXT NOT NULL
);

-- This node's own attestation issuer (an organization identity + a signing device)
CREATE TABLE IF NOT EXISTS node_issuer (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    identity_hash TEXT NOT NULL,
    master_signing_key TEXT NOT NULL,
    master_encryption_key TEXT NOT NULL,
    device_pubkey TEXT NOT NULL,
    device_signing_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- An issuer whose organization is OWNED by other identities: the organization's own key, the signing device, and the
-- founding genesis (signed by that key, waiting for the owners' approval)
CREATE TABLE IF NOT EXISTS owned_issuer (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    master_keys TEXT NOT NULL,
    device_keys TEXT NOT NULL,
    genesis_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- The organization this owned issuer acts for, once its owners have founded it (found by itself or given)
CREATE TABLE IF NOT EXISTS issuer_org (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    org_hash TEXT NOT NULL,
    found_at INTEGER NOT NULL
);

-- Explorer index (derived from sigchains; safe to rebuild)
CREATE TABLE IF NOT EXISTS explorer_identities (
    identity_hash TEXT PRIMARY KEY,
    name TEXT,
    identity_type TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_event_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    event_count INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    master_pubkey TEXT,
    device_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS explorer_events (
    event_hash TEXT PRIMARY KEY,
    identity_hash TEXT NOT NULL,
    idx INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    signed_by TEXT,
    summary TEXT NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_identity);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_identity);
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status);
CREATE INDEX IF NOT EXISTS idx_routing_hints_identity ON routing_hints(identity_hash);
CREATE INDEX IF NOT EXISTS idx_explorer_events_time ON explorer_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_explorer_events_identity ON explorer_events(identity_hash, idx);
CREATE INDEX IF NOT EXISTS idx_explorer_events_type ON explorer_events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_explorer_identities_recent ON explorer_identities(last_event_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_public_time ON messages(message_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_trust_delegations_to ON trust_delegations(to_identity);
CREATE INDEX IF NOT EXISTS idx_attestations_subject ON attestations(subject, claim_id);
CREATE INDEX IF NOT EXISTS idx_attestations_issuer ON attestations(issuer, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_attestations_time ON attestations(issued_at DESC);
"""


@dataclass
class Storage:
    """SQLite-based local storage."""

    db_path: Path
    _conn: sqlite3.Connection | None = None

    @classmethod
    def open(cls, db_path: Path | str) -> Storage:
        """Open or create a storage database."""
        db_path = Path(db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        storage = cls(db_path=db_path)
        storage._connect()
        storage._init_schema()
        return storage

    @classmethod
    def memory(cls) -> Storage:
        """Create an in-memory storage (for testing)."""
        storage = cls(db_path=Path(":memory:"))
        storage._conn = sqlite3.connect(":memory:", check_same_thread=False)
        storage._conn.row_factory = sqlite3.Row
        storage._init_schema()
        return storage

    def _connect(self) -> None:
        """Connect to the database."""
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def _init_schema(self) -> None:
        """Initialize the database schema."""
        with self.transaction() as cur:
            cur.executescript(SCHEMA)

            # Check/set schema version
            cur.execute("SELECT version FROM schema_version LIMIT 1")
            row = cur.fetchone()
            if row is None:
                cur.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))

            # IdentityAssertion was replaced by claims and attestations.
            cur.execute("DROP TABLE IF EXISTS trust_assertions")
            cur.execute("PRAGMA table_info(trust_delegations)")
            if "scope" not in {c["name"] for c in cur.fetchall()}:
                cur.execute("ALTER TABLE trust_delegations ADD COLUMN scope TEXT")

            # Databases created before the explorer index existed: build it once.
            cur.execute("SELECT COUNT(*) AS n FROM explorer_identities")
            if cur.fetchone()["n"] == 0:
                self._reindex_explorer(cur)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        """Context manager for a database transaction."""
        if self._conn is None:
            self._connect()

        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    # Identity operations

    def save_local_identity(self, identity: Identity, is_default: bool = False) -> None:
        """Save a local identity (one we control)."""
        if not identity.local_keypair:
            raise ValueError("Cannot save: not a local identity")

        import time

        with self.transaction() as cur:
            # If setting as default, clear other defaults
            if is_default:
                cur.execute("UPDATE local_identities SET is_default = 0")

            cur.execute(
                """
                INSERT OR REPLACE INTO local_identities
                (identity_hash, signing_key, encryption_key, is_default, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    identity.identity_hash,
                    identity.local_keypair.signing_key.to_hex(),
                    identity.local_keypair.encryption_key.to_hex(),
                    1 if is_default else 0,
                    int(time.time()),
                ),
            )

            # Also save the sigchain
            self._save_sigchain_internal(cur, identity.sigchain)

    def _save_sigchain_internal(self, cur: sqlite3.Cursor, sigchain: Sigchain) -> None:
        """Save a sigchain (internal, within transaction)."""
        import time

        cur.execute(
            """
            INSERT OR REPLACE INTO sigchains (identity_hash, sigchain_json, updated_at)
            VALUES (?, ?, ?)
            """,
            (sigchain.identity_hash, sigchain.to_json(), int(time.time())),
        )
        self._index_sigchain(cur, sigchain)

    def _index_sigchain(self, cur: sqlite3.Cursor, sigchain: Sigchain) -> None:
        """Refresh the explorer index rows for one identity (within a transaction)."""
        from nodetide.core.explorer_index import event_rows, identity_row

        row = identity_row(sigchain)
        if row is None:
            return
        cur.execute("DELETE FROM explorer_events WHERE identity_hash = ?", (row[0],))
        cur.executemany(
            """
            INSERT OR REPLACE INTO explorer_events
            (event_hash, identity_hash, idx, event_type, timestamp, signed_by, summary)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            event_rows(sigchain),
        )
        cur.execute(
            """
            INSERT OR REPLACE INTO explorer_identities
            (identity_hash, name, identity_type, created_at, last_event_at, updated_at,
             event_count, head_hash, master_pubkey, device_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            row,
        )

    def _reindex_explorer(self, cur: sqlite3.Cursor) -> None:
        cur.execute("SELECT sigchain_json FROM sigchains")
        for stored in cur.fetchall():
            try:
                chain = Sigchain.from_json(stored["sigchain_json"])
            except Exception:
                continue  # unreadable legacy row: leave it out of the index
            self._index_sigchain(cur, chain)

    def reindex_explorer(self) -> None:
        """Rebuild the explorer index from the stored sigchains."""
        with self.transaction() as cur:
            cur.execute("DELETE FROM explorer_events")
            cur.execute("DELETE FROM explorer_identities")
            self._reindex_explorer(cur)

    def save_sigchain(self, sigchain: Sigchain) -> None:
        """Save a sigchain (local or remote)."""
        with self.transaction() as cur:
            self._save_sigchain_internal(cur, sigchain)

    def get_local_identity(self, identity_hash: str) -> Identity | None:
        """Get a local identity by hash."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT signing_key, encryption_key FROM local_identities WHERE identity_hash = ?",
                (identity_hash,),
            )
            key_row = cur.fetchone()
            if not key_row:
                return None

            cur.execute(
                "SELECT sigchain_json FROM sigchains WHERE identity_hash = ?",
                (identity_hash,),
            )
            chain_row = cur.fetchone()
            if not chain_row:
                return None

            keypair = KeyPair.from_dict({
                "signing_key": key_row["signing_key"],
                "encryption_key": key_row["encryption_key"],
            })
            sigchain = Sigchain.from_json(chain_row["sigchain_json"])

            return Identity(sigchain=sigchain, local_keypair=keypair)

    def get_default_identity(self) -> Identity | None:
        """Get the default local identity."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT identity_hash FROM local_identities WHERE is_default = 1 LIMIT 1"
            )
            row = cur.fetchone()
            if not row:
                # Fall back to first identity
                cur.execute("SELECT identity_hash FROM local_identities LIMIT 1")
                row = cur.fetchone()

            if not row:
                return None

            return self.get_local_identity(row["identity_hash"])

    def list_local_identities(self) -> list[str]:
        """List all local identity hashes."""
        with self.transaction() as cur:
            cur.execute("SELECT identity_hash FROM local_identities ORDER BY created_at")
            return [row["identity_hash"] for row in cur.fetchall()]

    def list_all_sigchains(self) -> list[str]:
        """List all sigchain identity hashes (local and remote)."""
        with self.transaction() as cur:
            cur.execute("SELECT identity_hash FROM sigchains ORDER BY updated_at DESC")
            return [row["identity_hash"] for row in cur.fetchall()]

    def get_sigchain(self, identity_hash: str) -> Sigchain | None:
        """Get a sigchain by identity hash."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT sigchain_json FROM sigchains WHERE identity_hash = ?",
                (identity_hash,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return Sigchain.from_json(row["sigchain_json"])

    # Message operations

    def save_message(
        self,
        message_hash: str,
        bundle_json: str,
        sender_identity: str,
        recipient_identity: str | None,
        message_type: str,
        created_at: int,
        received_at: int | None = None,
        status: str = "pending",
    ) -> None:
        """Save a message."""
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO messages
                (message_hash, bundle_json, sender_identity, recipient_identity,
                 message_type, created_at, received_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_hash,
                    bundle_json,
                    sender_identity,
                    recipient_identity,
                    message_type,
                    created_at,
                    received_at,
                    status,
                ),
            )

    def get_message(self, message_hash: str) -> dict | None:
        """Get a message by hash."""
        with self.transaction() as cur:
            cur.execute("SELECT * FROM messages WHERE message_hash = ?", (message_hash,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_messages(
        self,
        identity_hash: str | None = None,
        sender_identity: str | None = None,
        message_type: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """List messages, optionally filtered."""
        query = "SELECT * FROM messages WHERE 1=1"
        params = []

        if identity_hash:
            query += " AND (sender_identity = ? OR recipient_identity = ?)"
            params.extend([identity_hash, identity_hash])

        if sender_identity:
            query += " AND sender_identity = ?"
            params.append(sender_identity)

        if message_type:
            query += " AND message_type = ?"
            params.append(message_type)

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.transaction() as cur:
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]

    def mark_message_read(self, message_hash: str) -> None:
        """Mark a message as read."""
        import time

        with self.transaction() as cur:
            cur.execute(
                "UPDATE messages SET read_at = ?, status = 'read' WHERE message_hash = ?",
                (int(time.time()), message_hash),
            )

    # Content operations

    def save_content_manifest(
        self,
        manifest_hash: str,
        manifest_json: str,
        content_hash: str,
        total_size: int,
    ) -> None:
        """Save a content manifest."""
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO content_manifests
                (manifest_hash, manifest_json, content_hash, total_size, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (manifest_hash, manifest_json, content_hash, total_size, int(time.time())),
            )

    def save_content_chunk(
        self,
        chunk_hash: str,
        data: bytes,
        manifest_hash: str | None = None,
        chunk_index: int | None = None,
    ) -> None:
        """Save a content chunk."""
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO content_chunks
                (chunk_hash, manifest_hash, chunk_index, data, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (chunk_hash, manifest_hash, chunk_index, data, int(time.time())),
            )

    def get_content_chunk(self, chunk_hash: str) -> bytes | None:
        """Get a content chunk by hash."""
        with self.transaction() as cur:
            cur.execute("SELECT data FROM content_chunks WHERE chunk_hash = ?", (chunk_hash,))
            row = cur.fetchone()
            return row["data"] if row else None

    # Routing hints

    def save_routing_hint(
        self,
        identity_hash: str,
        node_identity: str,
        cla_type: str,
        address: str,
        confidence: float = 1.0,
    ) -> None:
        """Save a routing hint."""
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO routing_hints
                (identity_hash, node_identity, cla_type, address, last_seen, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (identity_hash, node_identity, cla_type, address, int(time.time()), confidence),
            )

    def get_routing_hints(self, identity_hash: str) -> list[dict]:
        """Get routing hints for an identity."""
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT * FROM routing_hints
                WHERE identity_hash = ?
                ORDER BY last_seen DESC, confidence DESC
                """,
                (identity_hash,),
            )
            return [dict(row) for row in cur.fetchall()]

    # Trust operations

    def save_trust_delegation(
        self,
        from_identity: str,
        to_identity: str,
        weight: float,
        timestamp: int,
        depth_limit: int | None = None,
        scope: list[str] | None = None,
    ) -> None:
        """Save a trust delegation (replaces an earlier one for the same pair)."""
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO trust_delegations
                (from_identity, to_identity, weight, depth_limit, timestamp, scope)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    from_identity, to_identity, weight, depth_limit, timestamp,
                    json.dumps(scope) if scope is not None else None,
                ),
            )

    def get_trust_delegations(self, from_identity: str) -> list[dict]:
        """Get trust delegations from an identity."""
        with self.transaction() as cur:
            cur.execute(
                """
                SELECT * FROM trust_delegations
                WHERE from_identity = ?
                ORDER BY weight DESC
                """,
                (from_identity,),
            )
            rows = [dict(row) for row in cur.fetchall()]
        for row in rows:
            row["scope"] = json.loads(row["scope"]) if row.get("scope") else None
        return rows

    # Claims and attestations

    def save_claim_document(
        self, identity_hash: str, claim_id: str, claim_type: str, value: object, salt: str,
        published_at: int,
    ) -> None:
        """Store a published claim document (the holder consented by signing)."""
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO claim_documents
                (identity_hash, claim_id, claim_type, value_json, salt, published_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (identity_hash, claim_id, claim_type, json.dumps(value), salt, published_at),
            )

    def delete_claim_document(self, identity_hash: str, claim_id: str) -> bool:
        with self.transaction() as cur:
            cur.execute(
                "DELETE FROM claim_documents WHERE identity_hash = ? AND claim_id = ?",
                (identity_hash, claim_id),
            )
            return cur.rowcount > 0

    def get_claim_documents(self, identity_hash: str) -> dict[str, dict]:
        """Published claim documents of an identity, by claim_id."""
        with self.transaction() as cur:
            cur.execute("SELECT * FROM claim_documents WHERE identity_hash = ?", (identity_hash,))
            rows = [dict(r) for r in cur.fetchall()]
        return {
            r["claim_id"]: {
                "claim_id": r["claim_id"], "claim_type": r["claim_type"],
                "value": json.loads(r["value_json"]), "salt": r["salt"],
                "published_at": r["published_at"],
            }
            for r in rows
        }

    def save_attestation(self, attestation_id: str, body: dict) -> None:
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO attestations
                (attestation_id, subject, claim_id, claim_type, commitment, issuer, method,
                 assurance, issued_at, expires_at, body_json, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attestation_id, body["subject"], body["claim_id"], body["claim_type"],
                    body["commitment"], body.get("issuer"), body["method"], body["assurance"],
                    body["issued_at"], body["expires_at"], json.dumps(body), int(time.time()),
                ),
            )

    def get_attestation(self, attestation_id: str) -> dict | None:
        with self.transaction() as cur:
            cur.execute("SELECT body_json FROM attestations WHERE attestation_id = ?", (attestation_id,))
            row = cur.fetchone()
        return json.loads(row["body_json"]) if row else None

    def list_attestations(
        self, subject: str | None = None, claim_id: str | None = None, issuer: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Stored attestations (each with its id and whether the issuer revoked it)."""
        where, params = ["1=1"], []
        for column, value in (("a.subject", subject), ("a.claim_id", claim_id), ("a.issuer", issuer)):
            if value:
                where.append(f"{column} = ?")
                params.append(value)
        with self.transaction() as cur:
            cur.execute(
                f"""
                SELECT a.attestation_id, a.body_json, r.issued_at AS revoked_at, r.reason AS revoke_reason
                FROM attestations a
                LEFT JOIN attestation_revocations r ON r.attestation_id = a.attestation_id
                WHERE {" AND ".join(where)}
                ORDER BY a.issued_at DESC LIMIT ?
                """,
                [*params, limit],
            )
            rows = cur.fetchall()
        return [
            {
                "attestation_id": r["attestation_id"],
                "attestation": json.loads(r["body_json"]),
                "revoked_at": r["revoked_at"],
                "revoke_reason": r["revoke_reason"],
            }
            for r in rows
        ]

    def save_attestation_revocation(self, attestation_id: str, body: dict) -> None:
        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO attestation_revocations
                (attestation_id, issuer, reason, issued_at, body_json) VALUES (?, ?, ?, ?, ?)
                """,
                (attestation_id, body["issuer"], body.get("reason"), body["issued_at"], json.dumps(body)),
            )

    def get_attestation_revocation(self, attestation_id: str) -> dict | None:
        with self.transaction() as cur:
            cur.execute(
                "SELECT body_json FROM attestation_revocations WHERE attestation_id = ?",
                (attestation_id,),
            )
            row = cur.fetchone()
        return json.loads(row["body_json"]) if row else None

    def get_node_issuer(self) -> dict | None:
        with self.transaction() as cur:
            cur.execute("SELECT * FROM node_issuer WHERE id = 1")
            row = cur.fetchone()
        return dict(row) if row else None

    def save_node_issuer(
        self, identity_hash: str, master_signing_key: str, master_encryption_key: str,
        device_pubkey: str, device_signing_key: str,
    ) -> None:
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO node_issuer
                (id, identity_hash, master_signing_key, master_encryption_key,
                 device_pubkey, device_signing_key, created_at)
                VALUES (1, ?, ?, ?, ?, ?, ?)
                """,
                (identity_hash, master_signing_key, master_encryption_key,
                 device_pubkey, device_signing_key, int(time.time())),
            )

    def get_issuer_org(self) -> str | None:
        with self.transaction() as cur:
            cur.execute("SELECT org_hash FROM issuer_org WHERE id = 1")
            row = cur.fetchone()
        return row["org_hash"] if row else None

    def save_issuer_org(self, org_hash: str) -> None:
        import time

        with self.transaction() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO issuer_org (id, org_hash, found_at) VALUES (1, ?, ?)", (org_hash, int(time.time()))
            )

    def get_owned_issuer(self) -> dict | None:
        with self.transaction() as cur:
            cur.execute("SELECT * FROM owned_issuer WHERE id = 1")
            row = cur.fetchone()
        return dict(row) if row else None

    def save_owned_issuer(self, master_keys: str, device_keys: str, genesis_json: str) -> None:
        import time

        with self.transaction() as cur:
            cur.execute(
                "INSERT OR IGNORE INTO owned_issuer (id, master_keys, device_keys, genesis_json, created_at)"
                " VALUES (1, ?, ?, ?, ?)",
                (master_keys, device_keys, genesis_json, int(time.time())),
            )

    def set_default_identity(self, identity_hash: str) -> bool:
        """Set an existing local identity as the default.

        Returns True if successful, False if identity not found.
        """
        with self.transaction() as cur:
            # Check if identity exists
            cur.execute(
                "SELECT identity_hash FROM local_identities WHERE identity_hash = ?",
                (identity_hash,),
            )
            if not cur.fetchone():
                return False

            # Clear all defaults, then set the new one
            cur.execute("UPDATE local_identities SET is_default = 0")
            cur.execute(
                "UPDATE local_identities SET is_default = 1 WHERE identity_hash = ?",
                (identity_hash,),
            )
            return True

    # Relay operations

    def add_relayed_identity(
        self,
        identity_hash: str,
        distribution_points: list[str] | None = None,
    ) -> None:
        """Add an identity to relay."""
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO relayed_identities
                (identity_hash, distribution_points, added_at)
                VALUES (?, ?, ?)
                """,
                (
                    identity_hash,
                    json.dumps(distribution_points) if distribution_points else None,
                    int(time.time()),
                ),
            )

    def remove_relayed_identity(self, identity_hash: str) -> bool:
        """Remove an identity from relay. Returns True if it existed."""
        with self.transaction() as cur:
            cur.execute(
                "DELETE FROM relayed_identities WHERE identity_hash = ?",
                (identity_hash,),
            )
            return cur.rowcount > 0

    def list_relayed_identities(self) -> list[dict]:
        """List all relayed identities."""
        with self.transaction() as cur:
            cur.execute("SELECT * FROM relayed_identities ORDER BY added_at DESC")
            result = []
            for row in cur.fetchall():
                d = dict(row)
                if d.get("distribution_points"):
                    d["distribution_points"] = json.loads(d["distribution_points"])
                result.append(d)
            return result

    def get_relayed_identity(self, identity_hash: str) -> dict | None:
        """Get a relayed identity."""
        with self.transaction() as cur:
            cur.execute(
                "SELECT * FROM relayed_identities WHERE identity_hash = ?",
                (identity_hash,),
            )
            row = cur.fetchone()
            if row:
                d = dict(row)
                if d.get("distribution_points"):
                    d["distribution_points"] = json.loads(d["distribution_points"])
                return d
            return None

    def update_relayed_identity_poll(
        self,
        identity_hash: str,
        success: bool,
        error: str | None = None,
    ) -> None:
        """Update poll status for a relayed identity."""
        import time

        with self.transaction() as cur:
            cur.execute(
                """
                UPDATE relayed_identities
                SET last_polled_at = ?, last_poll_success = ?, poll_error = ?
                WHERE identity_hash = ?
                """,
                (int(time.time()), 1 if success else 0, error, identity_hash),
            )

    def update_relayed_identity_distribution_points(
        self,
        identity_hash: str,
        distribution_points: list[str],
    ) -> None:
        """Update distribution points for a relayed identity."""
        with self.transaction() as cur:
            cur.execute(
                """
                UPDATE relayed_identities
                SET distribution_points = ?
                WHERE identity_hash = ?
                """,
                (json.dumps(distribution_points), identity_hash),
            )

    def get_relay_config(self, key: str, default: str | None = None) -> str | None:
        """Get a relay configuration value."""
        with self.transaction() as cur:
            cur.execute("SELECT value FROM relay_config WHERE key = ?", (key,))
            row = cur.fetchone()
            return row["value"] if row else default

    def set_relay_config(self, key: str, value: str) -> None:
        """Set a relay configuration value."""
        with self.transaction() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO relay_config (key, value) VALUES (?, ?)",
                (key, value),
            )
