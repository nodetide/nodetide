"""Turning the environment into a running responder.

    NODETIDE_MAIL_RESPONDER=1                 switch it on
    NODETIDE_MAIL_ADDRESS                     the mailbox people write to (and the From of replies)
    NODETIDE_MAIL_IMAP_HOST / _PORT / _USER / _PASSWORD / _SECURITY (ssl|starttls|none) / _FOLDER
    NODETIDE_SMTP_HOST / _PORT / _USER / _PASSWORD / _SECURITY    replies go out through this (same as the verifier's)
    NODETIDE_MAIL_POLL_SECONDS                default 30
    NODETIDE_MAIL_REQUIRE_AUTH                default 1: only answer mail the receiving server found genuine (SPF/DKIM/DMARC)
    NODETIDE_MAIL_TRUSTED_SERVERS             comma-separated authserv-ids whose Authentication-Results are believed
                                              (usually the IMAP provider's name); unset = any, which only suits a mailbox
                                              that nobody else can write headers into
"""

from __future__ import annotations

import os

from nodetide.core.storage import Storage
from nodetide.mailresponder.imap import ImapMailbox, Poller
from nodetide.mailresponder.responder import Responder, ResponderConfig
from nodetide.verifiers.mail import SMTPSender


class MailResponderConfigError(Exception):
    pass


def enabled() -> bool:
    return os.environ.get("NODETIDE_MAIL_RESPONDER") == "1"


def smtp_from_env(from_addr: str) -> SMTPSender:
    host = os.environ.get("NODETIDE_SMTP_HOST")
    if not host:
        raise MailResponderConfigError("the mail responder needs NODETIDE_SMTP_HOST to send replies")
    return SMTPSender(
        host=host, port=int(os.environ.get("NODETIDE_SMTP_PORT", "587")),
        username=os.environ.get("NODETIDE_SMTP_USER") or None, password=os.environ.get("NODETIDE_SMTP_PASSWORD") or None,
        from_addr=from_addr, security=os.environ.get("NODETIDE_SMTP_SECURITY", "starttls"),
    )


def imap_from_env(prefix: str = "NODETIDE_MAIL_IMAP", max_bytes: int = 256 * 1024) -> ImapMailbox:
    host = os.environ.get(f"{prefix}_HOST")
    if not host:
        raise MailResponderConfigError(f"{prefix}_HOST is not set")
    return ImapMailbox(
        host=host, port=int(os.environ.get(f"{prefix}_PORT", "993")),
        username=os.environ.get(f"{prefix}_USER", ""), password=os.environ.get(f"{prefix}_PASSWORD", ""),
        security=os.environ.get(f"{prefix}_SECURITY", "ssl"), folder=os.environ.get(f"{prefix}_FOLDER", "INBOX"),
        max_bytes=max_bytes,
    )


def build(storage: Storage) -> tuple[Responder, Poller]:
    address = os.environ.get("NODETIDE_MAIL_ADDRESS", "").strip()
    if not address:
        raise MailResponderConfigError("NODETIDE_MAIL_RESPONDER=1 needs NODETIDE_MAIL_ADDRESS")
    trusted = [s.strip() for s in os.environ.get("NODETIDE_MAIL_TRUSTED_SERVERS", "").split(",") if s.strip()]
    config = ResponderConfig(
        address=address,
        require_auth=os.environ.get("NODETIDE_MAIL_REQUIRE_AUTH", "1") != "0",
        trusted_servers=trusted or None,
    )
    responder = Responder(storage, smtp_from_env(address), config)
    poller = Poller(imap_from_env(max_bytes=config.max_message_bytes), responder.handle,
                    interval=float(os.environ.get("NODETIDE_MAIL_POLL_SECONDS", "30")))
    return responder, poller
