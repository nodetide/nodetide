"""The request grammar and the reply format.

A request is plain text, one command per line:

    GET chain <identity_hash> [light] [since=<control_event_hash> [from=<n>]]
    GET content <identity_hash> <seq>
    GET info

Anything else in the message (greetings, signatures, quoted text) is ignored. A reply carries one attachment of
canonical-looking JSON (`application/vnd.nodetide+json`), split into `part`/`parts` when it is large.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from email.message import Message
from typing import Any

MEDIA_TYPE = ("application", "vnd.nodetide+json")
MAX_COMMANDS = 5
MAX_BODY_BYTES = 64 * 1024

_HASH = r"[0-9a-f]{64}"
_CHAIN = re.compile(rf"^get\s+chain\s+({_HASH})((?:\s+(?:light|since={_HASH}|from=\d{{1,9}}))*)\s*$", re.I)
_CONTENT = re.compile(rf"^get\s+content\s+({_HASH})\s+(\d{{1,9}})\s*$", re.I)
_INFO = re.compile(r"^get\s+info\s*$", re.I)


@dataclass(frozen=True)
class Command:
    kind: str                       # chain | content | info
    identity: str = ""
    light: bool = False
    since: str | None = None
    seq: int = 0
    content_from: int = 0           # with `since`: the asker already holds this many content events

    def line(self) -> str:
        if self.kind == "info":
            return "GET info"
        if self.kind == "content":
            return f"GET content {self.identity} {self.seq}"
        extra = (" light" if self.light else "") + (f" since={self.since}" if self.since else "") + (f" from={self.content_from}" if self.content_from else "")
        return f"GET chain {self.identity}{extra}"


def parse_line(line: str) -> Command | None:
    line = line.strip()
    if m := _CHAIN.match(line):
        options = m.group(2).split()
        since = next((o[6:].lower() for o in options if o.lower().startswith("since=")), None)
        start = next((int(o[5:]) for o in options if o.lower().startswith("from=")), 0)
        return Command("chain", m.group(1).lower(), light=any(o.lower() == "light" for o in options), since=since, content_from=start)
    if m := _CONTENT.match(line):
        return Command("content", m.group(1).lower(), seq=int(m.group(2)))
    if _INFO.match(line):
        return Command("info")
    return None


def parse_commands(body: str, subject: str = "") -> list[Command]:
    """Commands from the body (not from quoted lines or below a `-- ` signature mark); the subject only when the body has none."""
    found: list[Command] = []
    for raw in body.splitlines():
        if raw.rstrip() == "--":
            break
        if raw.lstrip().startswith(">"):
            continue
        command = parse_line(raw)
        if command and command not in found:
            found.append(command)
    if not found and (command := parse_line(subject)):
        found.append(command)
    return found[:MAX_COMMANDS]


def text_body(message: Message) -> str:
    """The text/plain part only, bounded; HTML and attachments are never looked at."""
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_type() == "text/plain" and part.get_content_disposition() != "attachment":
            payload = part.get_payload(decode=True) or b""
            return payload[:MAX_BODY_BYTES].decode(part.get_content_charset() or "utf-8", "replace")
    return ""


def dump(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
