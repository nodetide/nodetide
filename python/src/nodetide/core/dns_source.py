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
from nodetide.mailresponder.addresses import mailto_address

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


def apex_name(domain: str) -> str:
    """Where a domain lists the identities it hosts, in plain text: `_nodetide.<domain>`."""
    return f"{ZONE_LABEL}.{domain}"


# --- plain-text records ---------------------------------------------------------------------------------------------------
#
#   v=nt1; id=<identity hash>; dp=https://node.example.org; dp=mailto:chains@node.example.org
#
# Readable with `dig`, written by hand if need be, like SPF or DMARC. Unlike the signed state this is unauthenticated: it is
# only a list of *places to look*. Whatever is fetched from them is verified like anything else, so a forged or stale record
# can at worst send a reader to a place that has nothing (or that learns who asks).

PLAIN_VERSION = "nt1"
MAX_PLAIN_POINTS = 8
MAX_PLAIN_LENGTH = 1000
_PLAIN_SAFE = re.compile(r"^[\x21-\x7e]{1,200}$")        # printable ASCII, no space
_TAG = re.compile(r"^\s*([a-z]{1,8})\s*=\s*(\S*)\s*$")


def plain_point_ok(point: object) -> bool:
    """Can this distribution point be written in a plain record? One token: no space, no `;`, printable ASCII."""
    return isinstance(point, str) and bool(_PLAIN_SAFE.match(point)) and ";" not in point


def plain_record(identity_hash: str, points: list[str]) -> str:
    """The plain TXT value listing `points` for the identity. `dns:` points (the way to this record) and unwritable ones are left out."""
    chosen = [p for p in dict.fromkeys(points) if plain_point_ok(p) and not p.lower().startswith("dns:")][:MAX_PLAIN_POINTS]
    text = "; ".join([f"v={PLAIN_VERSION}", f"id={identity_hash}"] + [f"dp={p}" for p in chosen])
    if len(text) > MAX_PLAIN_LENGTH:
        raise ValueError("the plain record would be too long")
    return text


def parse_plain(text: object) -> dict | None:
    """{"id": hash, "dp": [points]} from a plain record, or None for anything else (the signed `nt1;` state, SPF, junk).
    Only points a reader may use are kept: http(s) URLs and plain mailboxes."""
    if not isinstance(text, str) or len(text) > MAX_PLAIN_LENGTH or text.startswith(PREFIX):
        return None
    tags: list[tuple[str, str]] = []
    for part in text.split(";"):
        m = _TAG.match(part)
        if not m:
            if part.strip():
                return None
            continue
        tags.append((m.group(1), m.group(2)))
    if not tags or tags[0] != ("v", PLAIN_VERSION):
        return None
    ids = [v for k, v in tags if k == "id"]
    if len(ids) != 1 or not _HASH.match(ids[0]):
        return None
    points = []
    for k, v in tags:
        if k == "dp" and len(points) < MAX_PLAIN_POINTS:
            if (v[:8].lower() in ("https://", ) or v[:7].lower() == "http://") and v not in points:
                points.append(v)
            elif mailto_address(v) and v not in points:
                points.append(v)
    return {"id": ids[0], "dp": points}


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
    """Fetches what an identity published in DNS: the signed state and the plain list of places to look. A short cache means
    a burst of requests asks DNS once."""

    def __init__(self, lookup: TxtLookup = system_txt_lookup, clock: Callable[[], float] = time.time):
        self._lookup, self._clock = lookup, clock
        self._cache: dict[str, tuple[float, list[str]]] = {}

    async def _values(self, name: str) -> list[str]:
        now = self._clock()
        cached = self._cache.get(name)
        if cached and now - cached[0] < CACHE_SECONDS:
            return cached[1]
        try:
            values = [v for v in (await self._lookup(name))[:16] if isinstance(v, str)]
        except Exception as e:
            logger.info("dns: lookup failed (%s)", type(e).__name__)
            values = []
        if len(self._cache) > 1000:
            self._cache.clear()
        self._cache[name] = (now, values)
        return values

    async def fetch(self, domain: str, identity_hash: str, max_age: int | None = None) -> VerifiedState | None:
        """The verified state published for `identity_hash` under `domain`, or None (nothing there, or nothing valid)."""
        if not _HASH.match(identity_hash or "") or dns_point(f"dns:{domain}") is None:
            return None
        now = int(self._clock())
        best: VerifiedState | None = None
        for value in (await self._values(record_name(domain, identity_hash)))[:8]:
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

    async def points(self, domain: str, identity_hash: str) -> list[str]:
        """The places the plain record at `<id>._nodetide.<domain>` lists for this identity (hints, not proof)."""
        if not _HASH.match(identity_hash or "") or dns_point(f"dns:{domain}") is None:
            return []
        out: list[str] = []
        for value in await self._values(record_name(domain, identity_hash)):
            plain = parse_plain(value)
            if plain and plain["id"] == identity_hash:
                out += [p for p in plain["dp"] if p not in out]
        return out[:MAX_PLAIN_POINTS]

    async def discover(self, domain: str) -> list[dict]:
        """The identities a domain lists in plain text at `_nodetide.<domain>`: [{"id", "dp"}]."""
        if dns_point(f"dns:{domain}") is None:
            return []
        found: dict[str, dict] = {}
        for value in await self._values(apex_name(domain)):
            plain = parse_plain(value)
            if plain:
                entry = found.setdefault(plain["id"], {"id": plain["id"], "dp": []})
                entry["dp"] += [p for p in plain["dp"] if p not in entry["dp"]]
        return list(found.values())[:50]
