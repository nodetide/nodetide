"""Compare what the zone holds with what we want, and apply the difference."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

from nodetide.dnspublish.records import Desired

Lookup = Callable[[str], Awaitable["list[str]"]]


@dataclass
class Plan:
    removes: list[tuple[str, str]] = field(default_factory=list)
    adds: list[tuple[str, str]] = field(default_factory=list)
    unchanged: list[tuple[str, str]] = field(default_factory=list)
    foreign: list[tuple[str, str]] = field(default_factory=list)      # other people's values at these names: never touched

    @property
    def empty(self) -> bool:
        return not self.removes and not self.adds


async def plan_publish(desired: Desired, lookup: Lookup) -> Plan:
    plan = Plan()
    for name, wanted in desired.records.items():
        current = await lookup(name)
        for value in current:
            if desired.is_ours(name, value):
                (plan.unchanged if value in wanted else plan.removes).append((name, value))
            else:
                plan.foreign.append((name, value))
        for value in wanted:
            if value not in current:
                plan.adds.append((name, value))
    return plan


async def plan_remove(desired: Desired, lookup: Lookup) -> Plan:
    """Take down everything of ours (state and plain list), leaving anything else."""
    plan = Plan()
    for name in desired.names:
        for value in await lookup(name):
            (plan.removes if desired.is_ours(name, value) else plan.foreign).append((name, value))
    return plan


def authoritative_lookup(server: str, port: int = 53, timeout: float = 5.0) -> Lookup:
    """TXT values straight from one name server (no cache), the way to see what an update really did."""
    async def lookup(name: str) -> list[str]:
        import dns.asyncquery
        import dns.exception
        import dns.message
        import dns.rcode
        query = dns.message.make_query(name if name.endswith(".") else name + ".", "TXT")
        try:
            answer = await dns.asyncquery.tcp(query, server, timeout=timeout, port=port)
        except (OSError, dns.exception.DNSException):
            return []
        if answer.rcode() != dns.rcode.NOERROR:
            return []
        return [b"".join(r.strings).decode("utf-8", "replace") for rrset in answer.answer if rrset.rdtype == 16 for r in rrset]
    return lookup
