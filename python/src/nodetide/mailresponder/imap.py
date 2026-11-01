"""Reads the responder's mailbox over IMAP and hands each new message to the responder."""

from __future__ import annotations

import asyncio
import imaplib
import logging
import ssl
from typing import Awaitable, Callable

logger = logging.getLogger(__name__)


class ImapMailbox:
    """Blocking IMAP access (run in an executor): fetch unseen messages, marking each seen *before* it is handled,
    so a crash loses a request (the client asks again) instead of answering it twice."""

    def __init__(self, host: str, port: int = 993, username: str = "", password: str = "", security: str = "ssl",
                 folder: str = "INBOX", max_bytes: int = 256 * 1024, batch: int = 20, timeout: int = 30):
        self.host, self.port, self.username, self.password = host, port, username, password
        self.security, self.folder, self.max_bytes, self.batch, self.timeout = security, folder, max_bytes, batch, timeout

    def _connect(self) -> imaplib.IMAP4:
        context = ssl.create_default_context()
        if self.security == "ssl":
            box: imaplib.IMAP4 = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=context, timeout=self.timeout)
        else:
            box = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
            if self.security == "starttls":
                box.starttls(context)
        box.login(self.username, self.password)
        return box

    def fetch_unseen(self, search: str = "UNSEEN", mark_seen: bool = True) -> list[bytes]:
        box = self._connect()
        try:
            box.select(self.folder)
            status, data = box.search(None, search)
            ids = data[0].split()[: self.batch] if status == "OK" and data and data[0] else []
            messages: list[bytes] = []
            for num in ids:
                status, size = box.fetch(num, "(RFC822.SIZE)")
                too_big = False
                if status == "OK" and size and size[0]:
                    text = size[0].decode() if isinstance(size[0], bytes) else str(size[0])
                    digits = text.rsplit("RFC822.SIZE", 1)[-1].strip(" )")
                    too_big = digits.isdigit() and int(digits) > self.max_bytes
                if too_big:
                    if mark_seen:
                        box.store(num, "+FLAGS", "\\Seen")
                    continue
                status, parts = box.fetch(num, "(BODY.PEEK[])")
                if mark_seen:
                    box.store(num, "+FLAGS", "\\Seen")
                if status == "OK" and parts and isinstance(parts[0], tuple):
                    messages.append(parts[0][1])
            return messages
        finally:
            try:
                box.logout()
            except Exception:
                pass


class Poller:
    def __init__(self, mailbox: ImapMailbox, handle: Callable[[bytes], Awaitable[int]], interval: float = 30.0):
        self.mailbox, self.handle, self.interval = mailbox, handle, interval
        self._task: asyncio.Task | None = None

    async def poll_once(self) -> int:
        loop = asyncio.get_running_loop()
        messages = await loop.run_in_executor(None, self.mailbox.fetch_unseen)
        for raw in messages:
            try:
                await self.handle(raw)
            except Exception:
                logger.exception("mail responder: a message could not be answered")
        return len(messages)

    async def _run(self) -> None:
        while True:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("mail responder: mailbox poll failed: %s", type(e).__name__)
            await asyncio.sleep(self.interval)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
