"""Reading an identity's published state (core/state.py) from DNS.

An identity names a domain in a distribution point, `dns:example.org`; the state lives in a TXT record at
`<first 32 hex of the identity hash>._nodetide.example.org` (a DNS label is at most 63 characters, the hash has 64).
DNS needs no trust here: the document is signed by the identity's master key and checked against the identity hash.
What DNS can still do is serve an old record or none, which is why a state carries an expiry and the caller decides
how old is too old.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Awaitable, Callable

from nodetide.core.state import PREFIX, StateError, VerifiedState, decode, verify_state

logger = logging.getLogger(__name__)

LABEL_PREFIX = 32
ZONE_LABEL = "_nodetide"
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BAD_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home.arpa", ".onion", ".invalid", ".test", ".example")
_HASH = re.compile(r"^[0-9a-f]{64}$")
CACHE_SECONDS = 60

TxtLookup = Callable[[str], Awaitable["list[str]"]]    # name -> the TXT values found, each already joined from its character-strings


def dns_point(point: object) -> str | None:
    """The domain of a `dns:` distribution point, or None: a plain public host name, lower-case ASCII, no IP literal."""
    if not isinstance(point, str) or len(point) > 260 or point[:4].lower() != "dns:":
        return None
    domain = point[4:].strip().lower().rstrip(".")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None
    if labels[-1].isdigit() or any(domain.endswith(s) for s in _BAD_SUFFIXES) or domain in ("localhost",):
        return None
    return domain


def dns_domains(points: object) -> list[str]:
    out: list[str] = []
    for point in points if isinstance(points, (list, tuple)) else []:
        domain = dns_point(point)
        if domain and domain not in out:
            out.append(domain)
    return out


def record_name(domain: str, identity_hash: str) -> str:
    return f"{identity_hash[:LABEL_PREFIX]}.{ZONE_LABEL}.{domain}"


async def system_txt_lookup(name: str, timeout: float = 5.0) -> list[str]:
    """TXT values at `name` through the system resolver (falls back to TCP when the answer does not fit a datagram)."""
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answer = await resolver.resolve(name, "TXT", raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.NoAnswer):
        return []
    return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer] if answer.rrset else []


class DnsStateSource:
    """Fetches and verifies states, with a short cache so a burst of requests asks DNS once."""

    def __init__(self, lookup: TxtLookup = system_txt_lookup, clock: Callable[[], float] = time.time):
        self._lookup, self._clock = lookup, clock
        self._cache: dict[tuple[str, str], tuple[float, VerifiedState | None]] = {}

    async def fetch(self, domain: str, identity_hash: str, max_age: int | None = None) -> VerifiedState | None:
        """The verified state published for `identity_hash` under `domain`, or None (nothing there, or nothing valid)."""
        if not _HASH.match(identity_hash or "") or dns_point(f"dns:{domain}") is None:
            return None
        key = (domain, identity_hash)
        now = self._clock()
        cached = self._cache.get(key)
        if cached and now - cached[0] < CACHE_SECONDS:
            return cached[1]
        state = await self._fetch(domain, identity_hash, int(now), max_age)
        if len(self._cache) > 1000:
            self._cache.clear()
        self._cache[key] = (now, state)
        return state

    async def _fetch(self, domain: str, identity_hash: str, now: int, max_age: int | None) -> VerifiedState | None:
        try:
            values = await self._lookup(record_name(domain, identity_hash))
        except Exception as e:
            logger.info("dns state: lookup failed (%s)", type(e).__name__)
            return None
        best: VerifiedState | None = None
        for value in values[:8]:
            if not value.startswith(PREFIX):
                continue
            try:
                state = verify_state(decode(value), expect_identity=identity_hash, now=now, max_age=max_age)
            except StateError as e:
                logger.info("dns state: a record was refused (%s)", e)
                continue
            if best is None or state.timestamp > best.timestamp:
                best = state
        return best
