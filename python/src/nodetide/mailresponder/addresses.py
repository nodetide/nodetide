"""mailto: distribution points."""

from __future__ import annotations

import re

_ADDRESS = re.compile(r"^[a-z0-9._%+\-]{1,64}@(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def mailto_address(point: object) -> str | None:
    """The mailbox of a `mailto:` distribution point, or None for anything else or anything doubtful.

    Strict on purpose: one plain address, no `?subject=&cc=` headers (RFC 6068 lets a link smuggle in recipients and
    content), no display name, no list, no percent-escapes, ASCII only. The distribution point comes from a chain
    anybody can publish, and we may end up sending mail to it.
    """
    if not isinstance(point, str) or len(point) > 320:
        return None
    text = point.strip()
    if text[:7].lower() != "mailto:":
        return None
    address = text[7:].lower()
    return address if _ADDRESS.match(address) else None


def mail_points(points: object) -> list[str]:
    """The mailboxes among a list of distribution points, in order, without repeats."""
    out: list[str] = []
    for point in points if isinstance(points, (list, tuple)) else []:
        address = mailto_address(point)
        if address and address not in out:
            out.append(address)
    return out
