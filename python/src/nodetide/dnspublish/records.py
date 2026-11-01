"""What to publish, and which values already in the zone are ours."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nodetide.core.dns_source import apex_name, parse_plain, plain_record, record_name
from nodetide.core.identity import Sigchain
from nodetide.core.crypto import KeyPair
from nodetide.core.state import PREFIX, build_state, encode


@dataclass
class Desired:
    """The records for one identity under one domain: {name: [TXT values]}, plus how to tell our values from other people's."""

    identity: str
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)

    @property
    def names(self) -> list[str]:
        return list(self.records)

    def is_ours(self, name: str, value: str) -> bool:
        """Is this existing value one we would have written (so that replacing may remove it)? At the identity's own name
        everything of ours looks like a state or a plain list for this identity; at the domain's name only a plain entry for
        this identity: other identities' entries there are theirs."""
        if name == apex_name(self.domain):
            return _plain_id(value) == self.identity
        if name == record_name(self.domain, self.identity):
            return value.startswith(PREFIX) or _plain_id(value) == self.identity
        return False


_ID = re.compile(r"(?:^|;)\s*id\s*=\s*([0-9a-f]{64})\s*(?:;|$)")


def _plain_id(value: str) -> str | None:
    """The identity a plain record is about, judged leniently (a record we are about to replace may be one we would no longer write)."""
    if not value.lstrip().startswith("v=nt1"):
        return None
    ids = _ID.findall(value)
    return ids[0] if len(ids) == 1 else None


def build_desired(chain: Sigchain, master: KeyPair, domain: str, validity: int, apex: bool = True, now: int | None = None) -> Desired:
    """The signed state and the plain list at the identity's name, and (optionally) the plain list at the domain's."""
    identity = chain.identity_hash
    points: list[str] = []
    for event in chain.events:
        points = getattr(event, "distribution_points", None) or points
    state = encode(build_state(chain, master, now=now, validity=validity))
    plain = plain_record(identity, points)
    records = {record_name(domain, identity): [state, plain]}
    if apex:
        records[apex_name(domain)] = [plain]
    return Desired(identity, domain, records)


def plain_matches(value: str, identity: str) -> bool:
    parsed = parse_plain(value)
    return bool(parsed and parsed["id"] == identity)
