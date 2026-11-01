"""Turning the environment into a running responder.

    NODETIDE_MAIL_RESPONDER=1                 switch it on
    NODETIDE_MAIL_ADDRESS                     the mailbox people write to (and the From of replies)
    NODETIDE_MAIL_IMAP_HOST / _PORT / _USER / _PASSWORD / _SECURITY (ssl|starttls|none) / _FOLDER
    NODETIDE_MAIL_SMTP_HOST / _PORT / _USER / _PASSWORD / _SECURITY    replies go out through this (submission on the same mail server)
    NODETIDE_MAIL_CA_FILE                     trust this certificate for IMAP and SMTP (a mail server with its own self-signed one)
    NODETIDE_MAIL_POLL_SECONDS                default 30
    NODETIDE_MAIL_REQUIRE_AUTH                default 1: only answer mail the receiving server found genuine (SPF/DKIM/DMARC)
    NODETIDE_MAIL_TRUSTED_SERVERS             comma-separated authserv-ids whose Authentication-Results are believed
                                              (usually the IMAP provider's name); unset = any, which only suits a mailbox
                                              that nobody else can write headers into
"""

from __future__ import annotations

import os

from nodetide.core.storage import Storage
from nodetide.mailresponder.fetch import MailFetchService, reply_dispatcher
from nodetide.mailresponder.imap import ImapMailbox, Poller
from nodetide.mailresponder.responder import Responder, ResponderConfig
from nodetide.verifiers.mail import SMTPSender


class MailResponderConfigError(Exception):
    pass


def enabled() -> bool:
    return os.environ.get("NODETIDE_MAIL_RESPONDER") == "1"


def smtp_from_env(from_addr: str, prefix: str = "NODETIDE_SMTP") -> SMTPSender:
    host = os.environ.get(f"{prefix}_HOST")
    if not host:
        raise MailResponderConfigError(f"{prefix}_HOST is not set (needed to send mail)")
    return SMTPSender(
        host=host, port=int(os.environ.get(f"{prefix}_PORT", "587")),
        username=os.environ.get(f"{prefix}_USER") or None, password=os.environ.get(f"{prefix}_PASSWORD") or None,
        from_addr=from_addr, security=os.environ.get(f"{prefix}_SECURITY", "starttls"),
        ca_file=os.environ.get("NODETIDE_MAIL_CA_FILE") or None,
    )


def imap_from_env(prefix: str = "NODETIDE_MAIL_IMAP", max_bytes: int = 256 * 1024) -> ImapMailbox:
    host = os.environ.get(f"{prefix}_HOST")
    if not host:
        raise MailResponderConfigError(f"{prefix}_HOST is not set")
    return ImapMailbox(
        host=host, port=int(os.environ.get(f"{prefix}_PORT", "993")),
        username=os.environ.get(f"{prefix}_USER", ""), password=os.environ.get(f"{prefix}_PASSWORD", ""),
        security=os.environ.get(f"{prefix}_SECURITY", "ssl"), folder=os.environ.get(f"{prefix}_FOLDER", "INBOX"),
        max_bytes=max_bytes, ca_file=os.environ.get("NODETIDE_MAIL_CA_FILE") or None,
    )


def build(storage: Storage) -> tuple[Responder, Poller, MailFetchService]:
    address = os.environ.get("NODETIDE_MAIL_ADDRESS", "").strip()
    if not address:
        raise MailResponderConfigError("NODETIDE_MAIL_RESPONDER=1 needs NODETIDE_MAIL_ADDRESS")
    trusted = [s.strip() for s in os.environ.get("NODETIDE_MAIL_TRUSTED_SERVERS", "").split(",") if s.strip()]
    config = ResponderConfig(
        address=address,
        require_auth=os.environ.get("NODETIDE_MAIL_REQUIRE_AUTH", "1") != "0",
        trusted_servers=trusted or None,
    )
    sender = smtp_from_env(address, "NODETIDE_MAIL_SMTP")
    responder = Responder(storage, sender, config)
    # answers from other nodes (to our own requests) are bigger than requests: the mailbox lets them through, the responder
    # still refuses oversized requests itself
    fetch = MailFetchService(sender, address, deliver=_no_fetcher)
    poller = Poller(imap_from_env(max_bytes=4 * 1024 * 1024), reply_dispatcher(responder, fetch),
                    interval=float(os.environ.get("NODETIDE_MAIL_POLL_SECONDS", "30")))
    return responder, poller, fetch


async def _no_fetcher(identity_hash, events) -> None:
    """Until the identity fetcher is attached (attach_fetcher)."""


def attach_fetcher(fetch: MailFetchService, fetcher) -> None:
    """Connect the node's identity fetcher: it asks by email as a last resort, and takes the answers."""
    if os.environ.get("NODETIDE_MAIL_FETCH", "1") == "0":
        return
    fetch.deliver = fetcher.deliver
    fetcher.mail = fetch
