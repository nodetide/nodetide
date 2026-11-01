"""Rate limits and sender checks: what keeps an answering machine from becoming a weapon."""

from __future__ import annotations

import re
import time
from collections import OrderedDict, deque
from email.message import Message
from email.utils import parseaddr

_SYSTEM_LOCALPARTS = {"mailer-daemon", "postmaster", "no-reply", "noreply", "do-not-reply", "bounce", "bounces"}


class SlidingLimit:
    """At most `count` units in any `window` seconds, per key (and old keys are forgotten)."""

    def __init__(self, count: int, window: float, clock=time.monotonic, max_keys: int = 10_000):
        self.count, self.window, self.clock, self.max_keys = count, window, clock, max_keys
        self._hits: OrderedDict[str, deque[tuple[float, int]]] = OrderedDict()

    def _live(self, key: str) -> deque[tuple[float, int]]:
        now = self.clock()
        hits = self._hits.pop(key, None) or deque()
        while hits and now - hits[0][0] >= self.window:
            hits.popleft()
        return hits

    def _store(self, key: str, hits: deque[tuple[float, int]]) -> None:
        if hits:
            self._hits[key] = hits
        while len(self._hits) > self.max_keys:
            self._hits.popitem(last=False)

    def fits(self, key: str, units: int = 1) -> bool:
        hits = self._live(key)
        self._store(key, hits)
        return sum(u for _, u in hits) + units <= self.count

    def allow(self, key: str, units: int = 1) -> bool:
        hits = self._live(key)
        ok = sum(u for _, u in hits) + units <= self.count
        if ok:
            hits.append((self.clock(), units))
        self._store(key, hits)
        return ok


def allow_all(*checks: tuple["SlidingLimit", str]) -> bool:
    """Count one unit against every limit, or against none when any of them is used up (a refused request costs nothing)."""
    if not all(limit.fits(key) for limit, key in checks):
        return False
    return all(limit.allow(key) for limit, key in checks)


class SeenIds:
    """Message-IDs already answered, bounded."""

    def __init__(self, size: int = 20_000):
        self.size, self._ids = size, OrderedDict()

    def add(self, message_id: str) -> bool:
        """True when new."""
        if not message_id:
            return True
        if message_id in self._ids:
            return False
        self._ids[message_id] = None
        while len(self._ids) > self.size:
            self._ids.popitem(last=False)
        return True


def sender_address(message: Message) -> str | None:
    """The one From address, lower-cased; None when absent, malformed or several. Reply-To is deliberately never used."""
    values = message.get_all("From") or []
    if len(values) != 1:
        return None
    addr = parseaddr(str(values[0]))[1].lower()
    return addr if re.fullmatch(r"[^@\s<>,;\"]+@[^@\s<>,;\"]+\.[^@\s<>,;\"]+", addr) else None


def is_automatic(message: Message, own_address: str = "") -> bool:
    """Bounces, auto-replies, list mail, and our own mail: never answered."""
    if str(message.get("Auto-Submitted", "no")).strip().lower() != "no":
        return True
    if str(message.get("Precedence", "")).strip().lower() in {"bulk", "list", "junk", "auto_reply"}:
        return True
    if any(message.get(h) for h in ("List-Id", "List-Unsubscribe", "X-Autoreply", "X-Autorespond", "X-Loop")):
        return True
    if str(message.get("Return-Path", "")).strip() == "<>":
        return True
    sender = sender_address(message) or ""
    if sender.partition("@")[0] in _SYSTEM_LOCALPARTS or (own_address and sender == own_address.lower()):
        return True
    return False


def _domain_matches(candidate: str, from_domain: str) -> bool:
    candidate = candidate.lower().strip(".")
    if "." not in candidate:
        return False
    return candidate == from_domain or candidate.endswith("." + from_domain) or from_domain.endswith("." + candidate)


def authenticated(message: Message, trusted_servers: list[str] | None = None) -> bool:
    """Did our own mail server find the From domain genuine? Reads Authentication-Results (RFC 8601) written by the
    server that received the mail; headers from other servers (anything an outsider could have added) are ignored
    when `trusted_servers` is given. Passes on dmarc=pass, or on spf/dkim=pass for the From domain itself."""
    sender = sender_address(message)
    if not sender:
        return False
    from_domain = sender.rpartition("@")[2]
    for header in message.get_all("Authentication-Results") or []:
        text = " ".join(str(header).split())
        server = text.split(";", 1)[0].strip().split()[0].lower() if text.split(";", 1)[0].strip() else ""
        if trusted_servers is not None and server not in {s.lower() for s in trusted_servers}:
            continue
        if re.search(r"\bdmarc=pass\b", text, re.I):
            return True
        for m in re.finditer(r"\bdkim=pass\b[^;]*?header\.(?:d|i)=@?([\w.-]+)", text, re.I):
            if _domain_matches(m.group(1), from_domain):
                return True
        for m in re.finditer(r"\bspf=pass\b[^;]*?smtp\.mailfrom=(?:[^@\s;]*@)?([\w.-]+)", text, re.I):
            if _domain_matches(m.group(1), from_domain):
                return True
    return False
