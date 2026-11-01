"""Answers mail that asks for sigchain data."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.message import EmailMessage, Message
from email.utils import formatdate, make_msgid
from typing import Any, Protocol

from nodetide.core.storage import Storage
from nodetide.mailresponder.limits import SeenIds, SlidingLimit, allow_all, authenticated, is_automatic, sender_address
from nodetide.mailresponder.protocol import MEDIA_TYPE, Command, dump, parse_commands, text_body

logger = logging.getLogger(__name__)

HELP = """This is a Nodetide node answering by email. Send one command per line:

  GET chain <identity_hash> [light] [since=<control_event_hash>]
  GET content <identity_hash> <seq>
  GET info

`light` returns only the control chain; `since=` returns only the control events after that one.
Replies carry the data as an attachment; check it against the chain's signatures, not against this message.
"""


class MessageSender(Protocol):
    async def send_message(self, message: EmailMessage) -> None: ...


@dataclass
class ResponderConfig:
    address: str                                  # our mailbox; also how we recognise our own mail
    require_auth: bool = True                     # demand a passing SPF/DKIM/DMARC result from our own mail server
    trusted_servers: list[str] | None = None      # authserv-ids whose Authentication-Results we believe
    max_message_bytes: int = 256 * 1024           # larger requests are dropped unread
    part_bytes: int = 1_000_000                   # one reply message
    max_parts: int = 6                            # a reply never exceeds part_bytes * max_parts
    per_sender: tuple[int, float] = (20, 3600.0)  # requests per sender per window
    per_domain: tuple[int, float] = (100, 3600.0)
    total: tuple[int, float] = (600, 3600.0)
    bytes_per_sender: tuple[int, float] = (20_000_000, 3600.0)


@dataclass
class Stats:
    answered: int = 0
    dropped: dict[str, int] = field(default_factory=dict)

    def drop(self, why: str) -> None:
        self.dropped[why] = self.dropped.get(why, 0) + 1
        logger.info("mail responder: a message was not answered (%s)", why)   # the reason only, never the address


class Responder:
    def __init__(self, storage: Storage, sender: MessageSender, config: ResponderConfig, clock=None):
        self.storage, self.sender, self.config = storage, sender, config
        kw = {"clock": clock} if clock else {}
        self._per_sender = SlidingLimit(*config.per_sender, **kw)
        self._per_domain = SlidingLimit(*config.per_domain, **kw)
        self._total = SlidingLimit(*config.total, **kw)
        self._bytes = SlidingLimit(*config.bytes_per_sender, **kw)
        self._seen = SeenIds()
        self.stats = Stats()

    # --- one incoming message -------------------------------------------------------------------------------------

    async def handle(self, raw: bytes) -> int:
        """Process one raw message; returns how many replies were sent. Never raises on a bad message."""
        cfg = self.config
        if len(raw) > cfg.max_message_bytes:
            self.stats.drop("too_large")
            return 0
        try:
            message = message_from_bytes(raw, policy=policy.default)
        except Exception:
            self.stats.drop("unparseable")
            return 0
        sender = sender_address(message)
        if not sender:
            self.stats.drop("no_sender")
            return 0
        if is_automatic(message, cfg.address):
            self.stats.drop("automatic")
            return 0
        if cfg.require_auth and not authenticated(message, cfg.trusted_servers):
            self.stats.drop("unauthenticated")
            return 0
        if not self._seen.add(str(message.get("Message-ID", "")).strip()):
            self.stats.drop("duplicate")
            return 0
        domain = sender.rpartition("@")[2]
        if not allow_all((self._total, "*"), (self._per_domain, domain), (self._per_sender, sender)):
            self.stats.drop("rate_limited")
            return 0

        commands = parse_commands(text_body(message), str(message.get("Subject", "")))
        replies: list[EmailMessage] = []
        if not commands:
            replies.append(self._reply(message, sender, "Nodetide: how to ask", HELP, None))
        for command in commands:
            replies += self._answer(message, sender, command)

        sent = 0
        for reply in replies:
            size = len(reply.as_bytes())
            if not self._bytes.allow(sender, size):
                self.stats.drop("byte_budget")
                break
            await self.sender.send_message(reply)
            sent += 1
        self.stats.answered += bool(sent)
        logger.info("mail responder: answered %d request(s) with %d message(s)", len(commands) or 1, sent)
        return sent

    # --- answering ------------------------------------------------------------------------------------------------

    def _answer(self, message: Message, sender: str, command: Command) -> list[EmailMessage]:
        subject = f"Re: {command.line()}"
        if command.kind == "info":
            return [self._reply(message, sender, subject, "Node information attached.\n", {
                "kind": "info", "commands": ["GET chain", "GET content", "GET info"],
                "limits": {"part_bytes": self.config.part_bytes, "max_parts": self.config.max_parts},
                "commit": os.environ.get("GIT_COMMIT", "dev"),
            })]
        chain = self.storage.get_sigchain(command.identity)
        if not chain:
            return [self._reply(message, sender, subject, f"No identity {command.identity} here.\n",
                                {"kind": "not_found", "identity_hash": command.identity})]
        if command.kind == "content":
            try:
                payload = chain.content_proof(command.seq) | {"kind": "content", "identity_hash": command.identity, "seq": command.seq}
            except (IndexError, ValueError):
                return [self._reply(message, sender, subject, "No such content event, or it is not committed yet.\n",
                                    {"kind": "not_found", "identity_hash": command.identity, "seq": command.seq})]
            return self._parts(message, sender, subject, payload, None)

        events = chain.to_list(light=command.light)
        control = len(chain.events)
        offset, since, skip = 0, None, 0
        if command.since:
            hashes = [e.event_hash() for e in chain.events]
            if command.since in hashes:
                offset, since = hashes.index(command.since) + 1, command.since
                skip = min(command.content_from, len(chain.content))
        head = {
            "kind": "chain", "identity_hash": command.identity, "head_hash": chain.head_hash or "",
            "control_length": control, "light": command.light, "since": since, "content_from": skip,
            "content_length": len(chain.content), "commitment": chain.content_commitment(), "content_head": chain.content_head,
        }
        # `since` trims the control chain, and `from=n` the content track (the asker holds its first n events)
        body_events = events[offset:control] + events[control + skip:]
        return self._parts(message, sender, subject, head, body_events)

    def _parts(self, message: Message, sender: str, subject: str, head: dict[str, Any], events: list[dict[str, Any]] | None) -> list[EmailMessage]:
        cfg = self.config
        chunks: list[list[dict[str, Any]] | None]
        if events is None:
            chunks = [None]
        else:
            chunks, current, size = [], [], 0
            for event in events:
                n = len(dump(event)) + 1
                if current and size + n > cfg.part_bytes:
                    chunks.append(current)
                    current, size = [], 0
                current.append(event)
                size += n
            chunks.append(current)
        if len(chunks) > cfg.max_parts:
            return [self._reply(message, sender, subject,
                                f"The answer would need {len(chunks)} messages (the limit is {cfg.max_parts}). "
                                "Ask for `light`, or use `since=` with the newest event you already hold.\n",
                                {"kind": "too_large", "identity_hash": head.get("identity_hash"), "parts_needed": len(chunks)})]
        out = []
        for i, chunk in enumerate(chunks, 1):
            payload = dict(head) | {"part": i, "parts": len(chunks)}
            if chunk is not None:
                payload["events"] = chunk
            label = f" (part {i} of {len(chunks)})" if len(chunks) > 1 else ""
            out.append(self._reply(message, sender, subject + label, "Data attached.\n", payload))
        return out

    def _reply(self, original: Message, to: str, subject: str, text: str, payload: dict[str, Any] | None) -> EmailMessage:
        reply = EmailMessage()
        reply["From"] = self.config.address
        reply["To"] = to
        reply["Subject"] = subject
        reply["Date"] = formatdate(localtime=False)
        reply["Message-ID"] = make_msgid(domain=self.config.address.rpartition("@")[2] or None)
        reply["Auto-Submitted"] = "auto-replied"
        reply["Precedence"] = "bulk"
        if mid := str(original.get("Message-ID", "")).strip():
            reply["In-Reply-To"] = mid
            reply["References"] = mid
        reply.set_content(text)
        if payload is not None:
            reply.add_attachment(dump(payload), maintype=MEDIA_TYPE[0], subtype=MEDIA_TYPE[1], filename="nodetide.json")
        return reply
