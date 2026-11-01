"""Asking other nodes for chains by email, without waiting: send now, take the answer when the poller sees it.

The node's identity fetcher uses this as a last resort for a `mailto:` distribution point when the HTTP sources did not
help. Requests go out only to addresses found in a chain's own signed distribution points, so they are rationed hard.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.message import Message
from typing import Any, Awaitable, Callable

from nodetide.core.identity import Sigchain
from nodetide.mailresponder.client import MailFetchError, build_request, chain_from_reply, join_parts, payloads
from nodetide.mailresponder.limits import SlidingLimit, sender_address
from nodetide.mailresponder.protocol import Command

logger = logging.getLogger(__name__)

MAX_PENDING = 200
MAX_AGE = 48 * 3600
MAX_PARTS = 20

DeliverFn = Callable[[str, list[dict[str, Any]]], Awaitable[None]]


@dataclass
class Pending:
    identity_hash: str
    address: str
    have: Sigchain | None
    created: float
    items: list[dict[str, Any]] = field(default_factory=list)


class MailFetchService:
    def __init__(self, sender, from_addr: str, deliver: DeliverFn, clock: Callable[[], float] = time.monotonic,
                 per_address: tuple[int, float] = (1, 3600.0), total: tuple[int, float] = (30, 3600.0)):
        self.sender, self.from_addr, self.deliver, self._clock = sender, from_addr, deliver, clock
        self._per_address = SlidingLimit(*per_address, clock=clock)
        self._total = SlidingLimit(*total, clock=clock)
        self.pending: OrderedDict[str, Pending] = OrderedDict()

    def _expire(self) -> None:
        now = self._clock()
        for key in [k for k, p in self.pending.items() if now - p.created > MAX_AGE]:
            del self.pending[key]
        while len(self.pending) > MAX_PENDING:
            self.pending.popitem(last=False)

    async def request(self, address: str, identity_hash: str, have: Sigchain | None = None) -> str:
        """Send one request. Returns "sent", or why not: "limited"."""
        self._expire()
        if address.lower() == self.from_addr.lower():
            return "limited"
        if any(p.address == address and p.identity_hash == identity_hash for p in self.pending.values()):
            return "waiting"                               # an answer to this very request may still come
        from nodetide.mailresponder.limits import allow_all
        if not allow_all((self._total, "*"), (self._per_address, address)):
            return "limited"
        have = have if have is not None and have.identity_hash == identity_hash else None
        command = Command("chain", identity_hash, since=have.head_hash if have else None,
                          content_from=len(have.content) if have else 0)
        message = build_request(self.from_addr, address, [command])
        self.pending[str(message["Message-ID"])] = Pending(identity_hash, address, have, self._clock())
        await self.sender.send_message(message)
        logger.info("mail fetch: asked a node for %s...", identity_hash[:12])
        return "sent"

    async def on_reply(self, message: Message) -> bool:
        """Take a message if it answers one of our requests. Returns True when it did (so nobody else handles it)."""
        key = str(message.get("In-Reply-To", "")).strip()
        pending = self.pending.get(key)
        if pending is None:
            return False
        if sender_address(message) != pending.address:      # only the address we asked may answer
            return False
        pending.items += payloads(message)
        kinds = {i.get("kind") for i in pending.items}
        if kinds & {"not_found", "too_large"}:
            logger.info("mail fetch: the node answered %s", sorted(kinds & {"not_found", "too_large"})[0])
            self.pending.pop(key, None)
            return True
        chain_items = [i for i in pending.items if i.get("kind") == "chain" and i.get("identity_hash") == pending.identity_hash]
        if not chain_items:
            return True
        if int(chain_items[0].get("parts", 1)) > MAX_PARTS:
            self.pending.pop(key, None)
            return True
        try:
            chain = chain_from_reply(join_parts(chain_items), pending.have)
        except MailFetchError as e:
            if str(e).startswith("incomplete"):
                return True                                  # more parts to come
            logger.info("mail fetch: an answer was refused (%s)", e)
            self.pending.pop(key, None)
            return True
        self.pending.pop(key, None)
        await self.deliver(pending.identity_hash, chain.to_list())
        return True


def reply_dispatcher(responder, fetch: MailFetchService | None):
    """One handler for the shared mailbox: answers to our own requests go to the fetch service, the rest to the responder."""
    async def dispatch(raw: bytes) -> int:
        if fetch is not None and fetch.pending and len(raw) <= responder.config.max_message_bytes * 40:
            message = message_from_bytes(raw, policy=policy.default)
            if await fetch.on_reply(message):
                return 0
        return await responder.handle(raw)
    return dispatch
