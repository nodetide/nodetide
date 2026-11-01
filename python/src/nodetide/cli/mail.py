"""`nodetide mail ...`: fetch sigchains from a node by email."""

from __future__ import annotations

import asyncio
import os

import click

from nodetide.mailresponder.client import MailClient, MailFetchError


@click.group("mail")
def mail():
    """Fetch data from a node that answers by email."""


@mail.command("fetch")
@click.argument("identity_hash")
@click.option("--to", "node_address", required=True, help="The node's mailbox, as listed in its mailto: distribution point")
@click.option("--from", "from_address", envvar="NODETIDE_MAIL_FROM", required=True, help="Your own mailbox (replies come here)")
@click.option("--light", is_flag=True, help="Control chain only; shown, not stored")
@click.option("--timeout", type=int, default=600, show_default=True, help="Seconds to wait for the reply")
def fetch(identity_hash: str, node_address: str, from_address: str, light: bool, timeout: int):
    """Ask NODE for IDENTITY_HASH's sigchain, verify it, and store it.

    Sends through NODETIDE_SMTP_* and reads the reply from NODETIDE_MAIL_CLIENT_IMAP_* (host, port, user, password, security).
    If the identity is already stored, only what is new is requested.
    """
    from nodetide.cli.main import get_storage
    from nodetide.mailresponder.config import MailResponderConfigError, imap_from_env, smtp_from_env

    try:
        client = MailClient(smtp_from_env(from_address), imap_from_env("NODETIDE_MAIL_CLIENT_IMAP"), from_address, node_address)
    except MailResponderConfigError as e:
        raise click.ClickException(str(e))
    storage = get_storage()
    have = storage.get_sigchain(identity_hash)
    click.echo("Request sent; waiting for the reply (this can take a few minutes)...")
    try:
        chain = asyncio.run(client.fetch_chain(identity_hash, have=have, light=light, timeout=timeout))
    except MailFetchError as e:
        raise click.ClickException(str(e))
    click.echo(f"Verified: {len(chain.events)} control events, {len(chain.content)} content events, head {chain.head_hash}")
    if light or chain.is_partial:
        click.echo("Light chain: not stored.")
    else:
        storage.save_sigchain(chain)
        click.echo("Stored.")
