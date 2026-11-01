"""Asking a node for sigchain data by email, and turning the reply into a verified chain."""

from __future__ import annotations

import asyncio
import json
import time
from email import message_from_bytes, policy
from email.message import EmailMessage, Message
from email.utils import formatdate, make_msgid
from typing import Any

from nodetide.core.identity import Sigchain
from nodetide.mailresponder.imap import ImapMailbox
from nodetide.mailresponder.protocol import MEDIA_TYPE, Command


class MailFetchError(Exception):
    """No usable answer: it never came, it was incomplete, or it did not verify."""


def build_request(from_addr: str, to_addr: str, commands: list[Command]) -> EmailMessage:
    message = EmailMessage()
    message["From"] = from_addr
    message["To"] = to_addr
    message["Subject"] = commands[0].line() if commands else "GET info"
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=from_addr.rpartition("@")[2] or None)
    message.set_content("\n".join(c.line() for c in commands) + "\n")
    return message


def payloads(raw: bytes | Message) -> list[dict[str, Any]]:
    """The JSON attachments of one reply (none if it has none)."""
    message = message_from_bytes(raw, policy=policy.default) if isinstance(raw, bytes) else raw
    out = []
    for part in message.walk():
        if (part.get_content_maintype(), part.get_content_subtype()) == MEDIA_TYPE:
            try:
                data = json.loads(part.get_payload(decode=True) or b"")
            except ValueError:
                continue
            if isinstance(data, dict):
                out.append(data)
    return out


def join_parts(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Several `part i of n` payloads of one answer into one; raises when any part is missing or they disagree."""
    if not items:
        raise MailFetchError("no data in the reply")
    parts = items[0].get("parts", 1)
    by_number = {int(i.get("part", 1)): i for i in items if i.get("kind") == items[0].get("kind")}
    if sorted(by_number) != list(range(1, parts + 1)):
        raise MailFetchError(f"incomplete: have parts {sorted(by_number)} of {parts}")
    first = dict(by_number[1])
    first["events"] = [e for n in sorted(by_number) for e in by_number[n].get("events", [])]
    for key in ("part", "parts"):
        first.pop(key, None)
    return first


def chain_from_reply(answer: dict[str, Any], have: Sigchain | None = None, resolve=None) -> Sigchain:
    """The chain a `GET chain` answer describes, verified. A `since` answer is joined onto `have`."""
    if answer.get("kind") != "chain":
        raise MailFetchError(f"not a chain answer ({answer.get('kind')})")
    events = list(answer.get("events", []))
    since = answer.get("since")
    if since:
        if have is None or since not in [e.event_hash() for e in have.events]:
            raise MailFetchError("the answer continues a chain we do not hold")
        cut = [e.event_hash() for e in have.events].index(since) + 1
        events = [e.to_dict() for e in have.events[:cut]] + [e.to_dict() for e in have.content[: int(answer.get("content_from", 0))]] + events
    try:
        chain = Sigchain.from_list(events)
    except Exception as e:
        raise MailFetchError(f"unreadable events: {type(e).__name__}") from e
    if chain.identity_hash != answer.get("identity_hash"):
        raise MailFetchError("the chain is not the identity asked for")
    ok, error = chain.verify(resolve=resolve)
    if not ok:
        raise MailFetchError(f"the chain does not verify: {error}")
    if answer.get("head_hash") and chain.head_hash != answer["head_hash"]:
        raise MailFetchError("the chain does not end where the answer says")
    return chain


class MailClient:
    def __init__(self, sender, mailbox: ImapMailbox, from_addr: str, to_addr: str):
        self.sender, self.mailbox, self.from_addr, self.to_addr = sender, mailbox, from_addr, to_addr

    async def ask(self, commands: list[Command], timeout: float = 300.0, interval: float = 10.0) -> list[dict[str, Any]]:
        """Send the request and wait for the reply (all parts of it); returns the payloads."""
        request = build_request(self.from_addr, self.to_addr, commands)
        mid = str(request["Message-ID"])
        await self.sender.send_message(request)
        loop = asyncio.get_running_loop()
        deadline = time.monotonic() + timeout
        found: list[dict[str, Any]] = []
        seen: set[str] = set()
        while time.monotonic() < deadline:
            raws = await loop.run_in_executor(None, lambda: self.mailbox.fetch_unseen(f'HEADER In-Reply-To "{mid}"', mark_seen=False))
            for raw in raws:
                message = message_from_bytes(raw, policy=policy.default)
                key = str(message.get("Message-ID", ""))
                if key in seen:
                    continue
                seen.add(key)
                found += payloads(message)
            if found and self._complete(found):
                return found
            await asyncio.sleep(interval)
        if found:
            return found
        raise MailFetchError("no reply before the timeout")

    @staticmethod
    def _complete(items: list[dict[str, Any]]) -> bool:
        # every answer in the batch has all its parts
        groups: dict[tuple, set[int]] = {}
        need: dict[tuple, int] = {}
        for i in items:
            k = (i.get("kind"), i.get("identity_hash"), i.get("seq"))
            groups.setdefault(k, set()).add(int(i.get("part", 1)))
            need[k] = int(i.get("parts", 1))
        return all(groups[k] == set(range(1, need[k] + 1)) for k in groups)

    async def fetch_chain(self, identity_hash: str, have: Sigchain | None = None, light: bool = False,
                          timeout: float = 300.0, interval: float = 10.0, resolve=None) -> Sigchain:
        since = have.head_hash if have is not None and have.identity_hash == identity_hash else None
        command = Command("chain", identity_hash, light=light, since=since, content_from=len(have.content) if since and have is not None else 0)
        items = await self.ask([command], timeout=timeout, interval=interval)
        mine = [i for i in items if i.get("identity_hash") == identity_hash]
        kinds = {i.get("kind") for i in mine}
        if "not_found" in kinds:
            raise MailFetchError("the node does not know this identity")
        if "too_large" in kinds:
            raise MailFetchError("the node refused: too large for email; ask for `light` or use since")
        return chain_from_reply(join_parts([i for i in mine if i.get("kind") == "chain"]), have, resolve)
