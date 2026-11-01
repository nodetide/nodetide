"""Outgoing mail for verification codes."""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Protocol

logger = logging.getLogger(__name__)


class MailError(Exception):
    """The message could not be handed to the mail server."""


class MailSender(Protocol):
    async def send(self, to: str, subject: str, body: str) -> None: ...


def build_message(from_addr: str, to: str, subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = from_addr
    message["To"] = to
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=from_addr.rpartition("@")[2] or None)
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(body)
    return message


class SMTPSender:
    """Sends through an SMTP server (STARTTLS by default)."""

    def __init__(
        self,
        host: str,
        port: int = 587,
        username: str | None = None,
        password: str | None = None,
        from_addr: str = "",
        security: str = "starttls",  # starttls | ssl | none
        timeout: int = 20,
        ca_file: str | None = None,  # trust this certificate (a server with its own self-signed one) instead of the system roots
    ):
        if security not in ("starttls", "ssl", "none"):
            raise ValueError("security must be starttls, ssl or none")
        if not from_addr:
            raise ValueError("a from address is required")
        self.host, self.port = host, port
        self.username, self.password = username, password
        self.from_addr, self.security, self.timeout, self.ca_file = from_addr, security, timeout, ca_file

    def _send_blocking(self, message: EmailMessage) -> None:
        context = ssl.create_default_context(cafile=self.ca_file)
        if self.security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=context)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        with server:
            server.ehlo()
            if self.security == "starttls":
                server.starttls(context=context)
                server.ehlo()
            if self.username:
                server.login(self.username, self.password or "")
            server.send_message(message)

    async def send_message(self, message: EmailMessage) -> None:
        """Send a finished message (attachments, threading headers)."""
        try:
            await asyncio.get_running_loop().run_in_executor(None, self._send_blocking, message)
        except (OSError, smtplib.SMTPException) as e:
            logger.warning("SMTP delivery failed: %s", type(e).__name__)
            raise MailError("could not send the email") from e

    async def send(self, to: str, subject: str, body: str) -> None:
        message = build_message(self.from_addr, to, subject, body)
        try:
            await asyncio.get_running_loop().run_in_executor(None, self._send_blocking, message)
        except (OSError, smtplib.SMTPException) as e:
            logger.warning("SMTP delivery failed: %s", type(e).__name__)
            raise MailError("could not send the verification email") from e


class LogSender:
    """Development only: writes the message, including the code, to the log."""

    async def send(self, to: str, subject: str, body: str) -> None:
        logger.warning("DEV MAIL to=%s subject=%s\n%s", to, subject, body)


class MemorySender:
    """Collects messages (tests)."""

    def __init__(self) -> None:
        self.outbox: list[dict[str, str]] = []
        self.messages: list[EmailMessage] = []   # whole messages sent with send_message
        self.fail = False

    async def send_message(self, message: EmailMessage) -> None:
        if self.fail:
            raise MailError("simulated delivery failure")
        self.messages.append(message)

    async def send(self, to: str, subject: str, body: str) -> None:
        if self.fail:
            raise MailError("simulated delivery failure")
        self.outbox.append({"to": to, "subject": subject, "body": body})
