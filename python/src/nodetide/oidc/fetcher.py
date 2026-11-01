"""Background fetcher for identities the node does not know yet.

When someone signs in with an unknown identity (or one whose sigchain is older
than what the signer has), the bridge schedules a fetch here and tells the
user "failed for now". Pending fetches are persisted, retried with backoff and
survive restarts, so a later sign-in finds the identity already known.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Awaitable, Callable, Iterable

from nodetide.core.auth import choose_sigchain
from nodetide.core.identity import Sigchain
from nodetide.core.storage import Storage
from nodetide.core.dns_source import dns_domains
from nodetide.mailresponder.addresses import mail_points
from nodetide.oidc.netguard import http_fetch_sigchain, validate_source_url

logger = logging.getLogger(__name__)

# Seconds to wait after the 1st, 2nd, ... failed attempt (last value repeats).
BACKOFF = (5, 15, 60, 300, 900, 3600)
MAX_AGE = 24 * 3600  # give up on an identity after a day
MAX_PENDING = 1000
MAX_SOURCES = 8
MAX_EVENTS = 1000
MIN_RETRY_GAP = 5  # a new sign-in may force a retry if the last one is older than this

IDENTITY_RE = re.compile(r"^[0-9a-f]{64}$")

FetchFn = Callable[[str, str], Awaitable["list[dict[str, Any]] | None"]]
UpdateFn = Callable[[str], Awaitable[None]]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS oidc_pending_fetches (
    identity_hash   TEXT PRIMARY KEY,
    hints           TEXT NOT NULL,
    want_head       TEXT,
    state           TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    last_attempt_at INTEGER,
    next_attempt_at INTEGER NOT NULL,
    last_error      TEXT
);
"""


class IdentityFetcher:
    """Persistent queue of identities to fetch, with a background worker."""

    def __init__(
        self,
        storage: Storage,
        seed_nodes: Iterable[str] = (),
        fetch: FetchFn | None = None,
        on_update: UpdateFn | None = None,
        lan_fetch: FetchFn | None = None,
        allow_private: bool = False,
        clock: Callable[[], float] = time.time,
    ):
        self._storage = storage
        self._allow_private = allow_private
        self._seeds = [
            u for u in (validate_source_url(s, allow_private) for s in seed_nodes) if u
        ]
        self._fetch: FetchFn = fetch or self._default_fetch
        self._lan_fetch: FetchFn = lan_fetch or self._default_lan_fetch
        self.dns = None    # DnsStateSource: plain `dp=` lists published at the identity's `dns:` points are more places to look
        self.lan = None    # LanSources: nodes found by mDNS on a network we are attached to (opt-in)
        self._on_update = on_update
        self._clock = clock
        self._task: asyncio.Task | None = None
        self._wake = asyncio.Event()
        self._running = False
        self.mail = None   # a MailFetchService: asks `mailto:` distribution points when the HTTP sources did not help
        with storage.transaction() as cur:
            cur.executescript(_SCHEMA)

    async def _default_fetch(self, base_url: str, identity_hash: str):
        return await http_fetch_sigchain(base_url, identity_hash, self._allow_private)

    async def _default_lan_fetch(self, base_url: str, identity_hash: str):
        return await http_fetch_sigchain(base_url, identity_hash, True)   # the address was vetted by LanSources

    # --- scheduling --------------------------------------------------------

    def schedule(
        self,
        identity_hash: str,
        hints: Iterable[str] = (),
        want_head: str | None = None,
    ) -> bool:
        """Queue a fetch. Returns False if the request is invalid or the queue is full.

        want_head: the fetch is only complete once a chain containing this
        event hash is stored (used when the signer is ahead of our copy).
        """
        if not isinstance(identity_hash, str) or not IDENTITY_RE.match(identity_hash):
            return False
        clean_hints = []
        for hint in hints:
            url = validate_source_url(hint, self._allow_private)
            if url and url not in clean_hints:
                clean_hints.append(url)
        clean_hints = clean_hints[:MAX_SOURCES]

        now = int(self._clock())
        with self._storage.transaction() as cur:
            cur.execute(
                "SELECT hints, want_head, state, last_attempt_at, next_attempt_at "
                "FROM oidc_pending_fetches WHERE identity_hash = ?",
                (identity_hash,),
            )
            row = cur.fetchone()
            if row is not None and row["state"] == "pending":
                merged = list(json.loads(row["hints"]))
                for url in clean_hints:
                    if url not in merged:
                        merged.append(url)
                merged = merged[:MAX_SOURCES]
                next_at = row["next_attempt_at"]
                last = row["last_attempt_at"]
                if last is None or now - last >= MIN_RETRY_GAP:
                    next_at = min(next_at, now)
                cur.execute(
                    "UPDATE oidc_pending_fetches SET hints = ?, want_head = ?, next_attempt_at = ? "
                    "WHERE identity_hash = ?",
                    (json.dumps(merged), want_head or row["want_head"], next_at, identity_hash),
                )
            else:
                if row is None:
                    cur.execute(
                        "SELECT COUNT(*) AS n FROM oidc_pending_fetches WHERE state = 'pending'"
                    )
                    if cur.fetchone()["n"] >= MAX_PENDING:
                        return False
                # New entry, or restart of a finished/abandoned one.
                cur.execute(
                    "INSERT OR REPLACE INTO oidc_pending_fetches "
                    "(identity_hash, hints, want_head, state, attempts, created_at, "
                    " last_attempt_at, next_attempt_at, last_error) "
                    "VALUES (?, ?, ?, 'pending', 0, ?, NULL, ?, NULL)",
                    (identity_hash, json.dumps(clean_hints), want_head, now, now),
                )
        self._wake.set()
        return True

    def status(self, identity_hash: str) -> dict[str, Any] | None:
        """Current state of a scheduled fetch, or None if never scheduled."""
        with self._storage.transaction() as cur:
            cur.execute(
                "SELECT state, attempts, last_attempt_at, next_attempt_at, last_error "
                "FROM oidc_pending_fetches WHERE identity_hash = ?",
                (identity_hash,),
            )
            row = cur.fetchone()
        return dict(row) if row is not None else None

    # --- processing --------------------------------------------------------

    def _satisfied(self, identity_hash: str, want_head: str | None) -> bool:
        stored = self._storage.get_sigchain(identity_hash)
        if stored is None:
            return False
        if want_head is None:
            return True
        return any(e.event_hash() == want_head for e in stored.events)

    def _ingest(self, identity_hash: str, events: list[dict[str, Any]]) -> bool:
        """Verify and store a fetched chain. Returns True if storage changed."""
        if not events or len(events) > MAX_EVENTS:
            return False
        try:
            chain = Sigchain.from_list(events)
        except Exception:
            return False
        valid, _ = chain.verify(self._storage.get_sigchain)
        if not valid or chain.identity_hash != identity_hash:
            # An organization is checked against its owners' chains: fetch the ones we lack, then this one is retried
            for owner in chain.get_owners() or []:
                identity = owner.get("identity") if isinstance(owner, dict) else None
                if isinstance(identity, str) and IDENTITY_RE.match(identity) and self._storage.get_sigchain(identity) is None:
                    self.schedule(identity, [])
            return False

        stored = self._storage.get_sigchain(identity_hash)
        best, conflict = choose_sigchain(stored, chain)
        if best is None or conflict:
            return False
        if stored is None or len(best.events) > len(stored.events):
            self._storage.save_sigchain(best)
            return True
        return False

    def _sources(self, identity_hash: str, hints: list[str], dns_points: list[str] = ()) -> list[str]:
        sources = list(hints)
        stored = self._storage.get_sigchain(identity_hash)
        if stored is not None:
            for event in stored.events:
                for point in getattr(event, "distribution_points", None) or []:
                    url = validate_source_url(point, self._allow_private)
                    if url and url not in sources:
                        sources.append(url)
        for point in dns_points:                      # published in DNS by the identity's domain: the same checks as any other source
            url = validate_source_url(point, self._allow_private)
            if url and url not in sources:
                sources.append(url)
        for seed in self._seeds:
            if seed not in sources:
                sources.append(seed)
        return sources[:MAX_SOURCES]

    def _own_points(self, identity_hash: str) -> list[str]:
        """The distribution points in the identity's own (signed) chain; the newest setting wins."""
        stored = self._storage.get_sigchain(identity_hash)
        points: list[str] = []
        for event in (stored.events if stored is not None else []):
            points = getattr(event, "distribution_points", None) or points
        return points

    async def _dns_points(self, identity_hash: str) -> list[str]:
        """Places the identity's `dns:` domains list for it in plain text. Hints from sign-in pages never lead to a DNS lookup."""
        if self.dns is None:
            return []
        out: list[str] = []
        for domain in dns_domains(self._own_points(identity_hash))[:3]:
            try:
                out += [p for p in await self.dns.points(domain, identity_hash) if p not in out]
            except Exception:
                logger.debug("dns points lookup failed for %s", identity_hash[:12])
        return out

    def _mail_sources(self, identity_hash: str, dns_points: list[str] = ()) -> list[str]:
        """Mailboxes among the identity's own (signed) distribution points and its DNS list; hints from sign-in pages are never mail."""
        return mail_points(list(self._own_points(identity_hash)) + list(dns_points))

    async def deliver(self, identity_hash: str, events: list[dict[str, Any]]) -> None:
        """A chain arrived by another channel (an email answer): verify, store, finish the fetch if it is satisfied."""
        if not isinstance(identity_hash, str) or not IDENTITY_RE.match(identity_hash):
            return
        updated = self._ingest(identity_hash, events)
        with self._storage.transaction() as cur:
            cur.execute("SELECT want_head, attempts, state FROM oidc_pending_fetches WHERE identity_hash = ?", (identity_hash,))
            row = cur.fetchone()
        if row is not None and row["state"] == "pending" and self._satisfied(identity_hash, row["want_head"]):
            self._finish(identity_hash, "done", row["attempts"], int(self._clock()), None)
        if updated and self._on_update is not None:
            try:
                await self._on_update(identity_hash)
            except Exception:
                logger.exception("on_update failed for %s", identity_hash[:16])

    async def _process(self, row: Any) -> None:
        identity_hash = row["identity_hash"]
        want_head = row["want_head"]
        now = int(self._clock())

        if now - row["created_at"] > MAX_AGE:
            self._finish(identity_hash, "abandoned", row["attempts"], now, "gave up after 24h")
            return

        updated = False
        error: str | None = None
        dns_points = await self._dns_points(identity_hash)
        for source in self._sources(identity_hash, json.loads(row["hints"]), dns_points):
            try:
                events = await self._fetch(source, identity_hash)
            except Exception as e:  # network errors, timeouts, blocked addresses
                error = f"{source}: {type(e).__name__}"
                continue
            if not events:
                error = f"{source}: not found"
                continue
            if self._ingest(identity_hash, events):
                updated = True
            if self._satisfied(identity_hash, want_head):
                break
            error = f"{source}: chain is older than required"

        # Nodes on the local network (found by mDNS, if switched on), then email
        if self.lan is not None and not self._satisfied(identity_hash, want_head):
            for source in self.lan.urls():
                try:
                    events = await self._lan_fetch(source, identity_hash)
                except Exception as e:
                    error = f"lan {type(e).__name__}"
                    continue
                if events and self._ingest(identity_hash, events):
                    updated = True
                if self._satisfied(identity_hash, want_head):
                    break
                error = "lan: no newer chain"

        # Last resort: ask by email. The answer comes later through deliver(); this attempt only sends the request.
        if self.mail is not None and not self._satisfied(identity_hash, want_head):
            asked = 0
            for address in self._mail_sources(identity_hash, dns_points):
                if asked >= 2:
                    break
                try:
                    outcome = await self.mail.request(address, identity_hash, self._storage.get_sigchain(identity_hash))
                except Exception as e:   # the mail server being down must not fail the fetch loop
                    outcome = f"failed ({type(e).__name__})"
                asked += outcome == "sent"
                error = f"mailto: {outcome}"

        attempts = row["attempts"] + 1
        if self._satisfied(identity_hash, want_head):
            self._finish(identity_hash, "done", attempts, now, None)
        else:
            delay = BACKOFF[min(attempts - 1, len(BACKOFF) - 1)]
            with self._storage.transaction() as cur:
                cur.execute(
                    "UPDATE oidc_pending_fetches SET attempts = ?, last_attempt_at = ?, "
                    "next_attempt_at = ?, last_error = ? WHERE identity_hash = ?",
                    (attempts, now, now + delay, error or "no sources", identity_hash),
                )

        # Notify after the row is updated so listeners see current status.
        if updated and self._on_update is not None:
            try:
                await self._on_update(identity_hash)
            except Exception:
                logger.exception("on_update failed for %s", identity_hash[:16])

    def _finish(self, identity_hash: str, state: str, attempts: int, now: int, error: str | None) -> None:
        with self._storage.transaction() as cur:
            cur.execute(
                "UPDATE oidc_pending_fetches SET state = ?, attempts = ?, last_attempt_at = ?, "
                "last_error = ? WHERE identity_hash = ?",
                (state, attempts, now, error, identity_hash),
            )

    async def run_once(self) -> int:
        """Process every fetch that is due. Returns how many were processed."""
        now = int(self._clock())
        with self._storage.transaction() as cur:
            cur.execute(
                "SELECT * FROM oidc_pending_fetches WHERE state = 'pending' "
                "AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT 10",
                (now,),
            )
            rows = cur.fetchall()
        for row in rows:
            await self._process(row)
        return len(rows)

    def _seconds_until_next(self) -> float:
        with self._storage.transaction() as cur:
            cur.execute(
                "SELECT MIN(next_attempt_at) AS t FROM oidc_pending_fetches WHERE state = 'pending'"
            )
            t = cur.fetchone()["t"]
        if t is None:
            return 60.0
        return max(1.0, min(60.0, t - self._clock()))

    # --- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("identity fetcher iteration failed")
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=self._seconds_until_next())
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
