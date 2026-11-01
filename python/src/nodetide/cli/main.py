"""Command-line interface for nodetide."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from nodetide.core.crypto import KeyPair
from nodetide.core.identity import Identity, IdentityType, DeviceCapability
from nodetide.core.storage import Storage
from nodetide.core.trust import (
    TrustDelegation,
    TrustGraph,
)
from nodetide.content.mime import create_text_message


def checked_points(points: tuple[str, ...]) -> list[str]:
    """Distribution points as given, but a mailto: one must be a plain address (what readers will accept)."""
    from nodetide.mailresponder.addresses import mailto_address
    for point in points:
        if point.strip()[:7].lower() == "mailto:" and mailto_address(point) is None:
            raise click.BadParameter(f"{point!r}: use a single plain address, like mailto:chains@node.example (no ?subject=, name or list)")
    return list(points)


def data_dir() -> Path:
    """Where the CLI keeps its database: $NODETIDE_HOME, else ~/.nodetide."""
    return Path(os.environ["NODETIDE_HOME"]) if os.environ.get("NODETIDE_HOME") else Path.home() / ".nodetide"


def get_storage() -> Storage:
    """Get the default storage."""
    return Storage.open(data_dir() / "nodetide.db")


def get_default_identity(storage: Storage) -> Identity | None:
    """Get the default identity."""
    return storage.get_default_identity()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Nodetide - Distributed identity and messaging."""
    pass


from nodetide.cli.claims import claim as claim_group, eid as eid_group  # noqa: E402

from nodetide.cli.mail import mail as mail_group  # noqa: E402

cli.add_command(claim_group)
cli.add_command(eid_group)
cli.add_command(mail_group)

# Identity commands


@cli.group()
def identity():
    """Identity management commands."""
    pass


@identity.command("create")
@click.option("--name", "-n", help="Display name for the identity")
@click.option("--type", "identity_type", type=click.Choice(["personal", "organization", "ephemeral"]), default="personal")
@click.option("--distribution", "-d", multiple=True, help="Distribution point URI (can be specified multiple times)")
@click.option("--default/--no-default", default=True, help="Set as default identity")
def identity_create(name: str | None, identity_type: str, distribution: tuple[str, ...], default: bool):
    """Create a new identity.

    Distribution points are URIs where this identity can be reached, e.g.:
      -d https://relay.example.com/api
      -d tcp://node.example.com:4557
    """
    storage = get_storage()

    id_type = IdentityType(identity_type)
    dist_points = checked_points(distribution) if distribution else None
    ident = Identity.create(identity_type=id_type, name=name, distribution_points=dist_points)

    # Save to storage
    storage.save_local_identity(ident, is_default=default)
    storage.close()

    click.echo(f"Created identity: {ident.identity_hash}")
    if name:
        click.echo(f"Name: {name}")
    click.echo(f"Type: {identity_type}")
    if dist_points:
        click.echo(f"Distribution points: {', '.join(dist_points)}")


@identity.command("list")
def identity_list():
    """List all local identities."""
    storage = get_storage()

    identities = storage.list_local_identities()
    default = storage.get_default_identity()
    default_hash = default.identity_hash if default else None

    storage.close()

    if not identities:
        click.echo("No identities found. Create one with: nodetide identity create")
        return

    for identity_hash in identities:
        marker = "*" if identity_hash == default_hash else " "
        click.echo(f"{marker} {identity_hash}")


@identity.command("show")
@click.argument("identity_hash", required=False)
def identity_show(identity_hash: str | None):
    """Show identity details."""
    storage = get_storage()

    if identity_hash:
        ident = storage.get_local_identity(identity_hash)
        if not ident:
            # Try to get sigchain for remote identity
            sigchain = storage.get_sigchain(identity_hash)
            if sigchain:
                click.echo(f"Identity: {identity_hash} (remote)")
                click.echo(f"Events: {len(sigchain.events)}")
                genesis = sigchain.genesis
                if genesis and genesis.name:
                    click.echo(f"Name: {genesis.name}")
                return
            click.echo(f"Identity not found: {identity_hash}")
            return
    else:
        ident = get_default_identity(storage)
        if not ident:
            click.echo("No default identity. Create one with: nodetide identity create")
            return

    storage.close()

    click.echo(f"Identity: {ident.identity_hash}")
    genesis = ident.sigchain.genesis
    if genesis:
        if genesis.name:
            click.echo(f"Name: {genesis.name}")
        click.echo(f"Type: {genesis.identity_type.value}")
        click.echo(f"Created: {genesis.timestamp}")

    # Get distribution points by iterating events (consumer logic)
    dist_points: list[str] = []
    for event in ident.sigchain.events:
        if hasattr(event, 'distribution_points') and event.distribution_points:
            dist_points = event.distribution_points
    if dist_points:
        click.echo(f"Distribution points:")
        for dp in dist_points:
            click.echo(f"  - {dp}")

    click.echo(f"Events: {len(ident.sigchain.events)}")

    devices = ident.sigchain.get_active_devices()
    if devices:
        click.echo(f"Active devices: {len(devices)}")
        for device in devices:
            click.echo(f"  - {device.label} ({device.pubkey[:16]}...)")

    # Verify sigchain
    valid, error = ident.verify()
    if valid:
        click.echo("Sigchain: valid")
    else:
        click.echo(f"Sigchain: INVALID - {error}")


@identity.command("add-device")
@click.option("--label", "-l", required=True, help="Label for the device")
@click.option("--expires", type=int, help="Expiration timestamp (optional)")
def identity_add_device(label: str, expires: int | None):
    """Add a device key to your identity."""
    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one with: nodetide identity create")
        return

    device_keypair, event = ident.add_device(label=label, expires=expires)

    # Save updated identity
    storage.save_sigchain(ident.sigchain)
    storage.close()

    click.echo(f"Added device: {label}")
    click.echo(f"Device public key: {device_keypair.verify_key.to_hex()}")
    click.echo(f"Device signing key (SAVE THIS): {device_keypair.signing_key.to_hex()}")


@identity.command("revoke-device")
@click.argument("device_pubkey")
@click.option("--reason", "-r", help="Reason for revocation")
def identity_revoke_device(device_pubkey: str, reason: str | None):
    """Revoke a device key."""
    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one with: nodetide identity create")
        return

    event = ident.revoke_device(device_pubkey, reason=reason)

    storage.save_sigchain(ident.sigchain)
    storage.close()

    click.echo(f"Revoked device: {device_pubkey[:16]}...")


@identity.command("set-distribution")
@click.option("--distribution", "-d", multiple=True, required=True, help="Distribution point URI (can be specified multiple times)")
def identity_set_distribution(distribution: tuple[str, ...]):
    """Set or update distribution points.

    Distribution points are URIs where this identity can be reached.
    This replaces all existing distribution points.

    Example:
      nodetide identity set-distribution -d https://relay.example.com -d mailto:me@example.com
    """
    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one with: nodetide identity create")
        return

    dist_points = checked_points(distribution)
    event = ident.set_distribution_points(dist_points)

    storage.save_sigchain(ident.sigchain)
    storage.close()

    click.echo("Updated distribution points:")
    for dp in dist_points:
        click.echo(f"  - {dp}")


@identity.command("set-recovery")
@click.option("--trustees", "-t", required=True, help="Comma-separated trustee identity hashes")
@click.option("--threshold", "-n", type=int, required=True, help="Number of trustees required for recovery")
def identity_set_recovery(trustees: str, threshold: int):
    """Set recovery trustees."""
    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one with: nodetide identity create")
        return

    trustee_list = [t.strip() for t in trustees.split(",")]

    if threshold > len(trustee_list):
        click.echo("Threshold cannot be greater than number of trustees")
        return

    if threshold < 1:
        click.echo("Threshold must be at least 1")
        return

    event = ident.set_recovery(
        primary_trustees=trustee_list,
        primary_threshold=threshold,
    )

    storage.save_sigchain(ident.sigchain)
    storage.close()

    click.echo(f"Set recovery: {threshold} of {len(trustee_list)} trustees")


@identity.command("export")
@click.argument("output_file", type=click.Path())
def identity_export(output_file: str):
    """Export identity sigchain to file."""
    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one with: nodetide identity create")
        return

    storage.close()

    with open(output_file, "w") as f:
        f.write(ident.sigchain.to_json())

    click.echo(f"Exported sigchain to {output_file}")


@identity.command("import")
@click.argument("input_file", type=click.Path(exists=True))
def identity_import(input_file: str):
    """Import identity sigchain from file."""
    from nodetide.core.identity import Sigchain

    storage = get_storage()

    with open(input_file, "r") as f:
        sigchain = Sigchain.from_json(f.read())

    # Verify sigchain
    valid, error = sigchain.verify()
    if not valid:
        click.echo(f"Invalid sigchain: {error}")
        return

    storage.save_sigchain(sigchain)
    storage.close()

    click.echo(f"Imported sigchain: {sigchain.identity_hash}")


@identity.command("select")
@click.argument("identity_hash")
def identity_select(identity_hash: str):
    """Select an identity as the default/active identity."""
    storage = get_storage()

    # Support partial hash matching
    identities = storage.list_local_identities()
    matches = [h for h in identities if h.startswith(identity_hash)]

    if not matches:
        click.echo(f"No identity found matching: {identity_hash}")
        click.echo("Available identities:")
        for h in identities:
            click.echo(f"  {h}")
        storage.close()
        return

    if len(matches) > 1:
        click.echo(f"Ambiguous hash prefix. Matches:")
        for h in matches:
            click.echo(f"  {h}")
        storage.close()
        return

    full_hash = matches[0]
    if storage.set_default_identity(full_hash):
        click.echo(f"Selected identity: {full_hash}")
    else:
        click.echo(f"Failed to select identity: {full_hash}")

    storage.close()


@identity.command("dump")
@click.argument("output_file", type=click.Path())
@click.option("--password", "-p", prompt=True, hide_input=True, confirmation_prompt=True,
              help="Password to encrypt the dump")
def identity_dump(output_file: str, password: str):
    """Dump identity with encrypted private keys.

    Creates a complete backup including private keys, encrypted with a password.
    This can be restored on another device with 'identity restore'.

    The dump format is compatible with the web client.
    """
    from nodetide.core.crypto import password_encrypt

    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one with: nodetide identity create")
        storage.close()
        return

    if not ident.local_keypair:
        click.echo("Cannot dump: no local keys for this identity")
        storage.close()
        return

    storage.close()

    # Prepare the data to encrypt (private keys)
    keys_data = json.dumps(ident.local_keypair.to_dict()).encode("utf-8")
    encrypted_keys = password_encrypt(keys_data, password)

    # Create the dump (format compatible with web client)
    dump = {
        "version": 1,
        "format": "nodetide-identity-dump",
        "identity_hash": ident.identity_hash,
        "sigchain": ident.sigchain.to_list(),
        "encrypted_keys": encrypted_keys,  # hex string, PBKDF2+AES-GCM
    }

    with open(output_file, "w") as f:
        json.dump(dump, f, indent=2)

    click.echo(f"Identity dumped to {output_file}")
    click.echo(f"Identity hash: {ident.identity_hash}")
    click.echo("Keep this file and password safe - they contain your private keys!")


@identity.command("restore")
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--password", "-p", prompt=True, hide_input=True,
              help="Password to decrypt the dump")
@click.option("--default/--no-default", default=True, help="Set as default identity")
def identity_restore(input_file: str, password: str, default: bool):
    """Restore identity from encrypted dump.

    Restores a complete identity including private keys from a dump file
    created with 'identity dump' or exported from the web client.
    """
    from nodetide.core.crypto import password_decrypt
    from nodetide.core.identity import Sigchain

    storage = get_storage()

    # Load the dump
    with open(input_file, "r") as f:
        dump = json.load(f)

    # Validate format
    if dump.get("format") != "nodetide-identity-dump":
        click.echo("Invalid dump file format")
        storage.close()
        return

    version = dump.get("version", 1)
    if version != 1:
        click.echo(f"Unsupported dump version: {version}")
        storage.close()
        return

    # Decrypt private keys (encrypted_keys is a hex string)
    try:
        keys_data = password_decrypt(dump["encrypted_keys"], password)
        keypair = KeyPair.from_dict(json.loads(keys_data.decode("utf-8")))
    except ValueError as e:
        click.echo(f"Failed to decrypt: {e}")
        storage.close()
        return

    # Parse and verify sigchain
    sigchain = Sigchain.from_list(dump["sigchain"])
    valid, error = sigchain.verify()
    if not valid:
        click.echo(f"Invalid sigchain: {error}")
        storage.close()
        return

    # Verify the keypair matches the sigchain
    if keypair.verify_key.to_hex() != sigchain.genesis.pubkey:
        click.echo("Error: Private key does not match sigchain public key")
        storage.close()
        return

    # Create identity and save
    ident = Identity(sigchain=sigchain, local_keypair=keypair)
    storage.save_local_identity(ident, is_default=default)
    storage.close()

    click.echo(f"Identity restored: {ident.identity_hash}")
    if default:
        click.echo("Set as default identity")


# Trust commands


@cli.group()
def trust():
    """Trust management commands."""
    pass


@trust.command("delegate")
@click.argument("identity_hash")
@click.option("--weight", "-w", type=float, default=0.5, help="Trust weight (0.0 to 1.0)")
@click.option("--depth", "-d", type=int, help="Maximum delegation depth")
@click.option("--scope", "-s", help="Comma-separated claim types this covers (default: all)")
def trust_delegate(identity_hash: str, weight: float, depth: int | None, scope: str | None):
    """Trust someone to issue attestations (e.g. verify legal names)."""
    import time

    scope_list = [t.strip() for t in scope.split(",") if t.strip()] if scope else None

    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one first.")
        return

    storage.save_trust_delegation(
        from_identity=ident.identity_hash,
        to_identity=identity_hash,
        weight=weight,
        timestamp=int(time.time()),
        depth_limit=depth,
        scope=scope_list,
    )
    storage.close()

    covers = ", ".join(scope_list) if scope_list else "all claim types"
    click.echo(f"Delegated trust to {identity_hash[:16]}... with weight {weight} for {covers}")


@trust.command("show")
@click.argument("identity_hash")
@click.option("--claim-type", "-c", help="Only consider this claim type")
def trust_show(identity_hash: str, claim_type: str | None):
    """Show how much you trust an identity to issue attestations."""
    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity.")
        return

    graph = TrustGraph(my_identity=ident.identity_hash)
    frontier, seen = [ident.identity_hash], {ident.identity_hash}
    for _ in range(3):
        next_frontier = []
        for identity in frontier:
            for d in storage.get_trust_delegations(identity):
                graph.add_delegation(TrustDelegation.from_dict(d))
                if d["to_identity"] not in seen:
                    seen.add(d["to_identity"])
                    next_frontier.append(d["to_identity"])
        frontier = next_frontier
    storage.close()

    result = graph.calculate_trust(identity_hash, claim_type)
    click.echo(f"Trust in {identity_hash[:16]}...: {result.trust_score:.2f}")
    for path in result.paths:
        hops = " -> ".join(h[:8] for h in path.hops)
        click.echo(f"  {hops}  ({path.combined_score:.2f})")
    if not result.paths:
        click.echo("  No delegation path from you")


# Message commands


@cli.group()
def message():
    """Message commands."""
    pass


@message.command("send")
@click.argument("recipient")
@click.option("--text", "-t", help="Text message to send")
@click.option("--file", "-f", "file_path", type=click.Path(exists=True), help="File to send")
def message_send(recipient: str, text: str | None, file_path: str | None):
    """Send a message."""
    from nodetide.content.mime import Content, MultipartContent

    if not text and not file_path:
        click.echo("Provide --text or --file")
        return

    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one first.")
        return

    # Build content
    if text and file_path:
        mp = MultipartContent.mixed()
        mp.add_text(text)
        mp.add_file(file_path)
        content = mp.to_dict()
    elif text:
        content = create_text_message(text)
    else:
        content = Content.from_file(file_path).to_dict()

    # For now, just show what would be sent
    # Actual sending requires daemon
    click.echo(f"Would send to: {recipient}")
    click.echo(f"Content: {json.dumps(content, indent=2)[:200]}...")
    click.echo("\nNote: Start daemon to actually send messages")


@message.command("list")
@click.option("--limit", "-n", type=int, default=20, help="Number of messages to show")
def message_list(limit: int):
    """List messages."""
    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity.")
        return

    messages = storage.list_messages(identity_hash=ident.identity_hash, limit=limit)
    storage.close()

    if not messages:
        click.echo("No messages")
        return

    for msg in messages:
        direction = "→" if msg["sender_identity"] == ident.identity_hash else "←"
        other = msg["recipient_identity"] if direction == "→" else msg["sender_identity"]
        other_short = (other or "broadcast")[:12]
        click.echo(f"{direction} {other_short}... [{msg['message_type']}] {msg['status']}")


# Daemon commands


@cli.group()
def daemon():
    """Daemon commands."""
    pass


@daemon.command("start")
@click.option("--port", "-p", type=int, default=4556, help="Port to listen on")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground")
def daemon_start(port: int, foreground: bool):
    """Start the relay daemon."""
    import asyncio
    from nodetide.daemon.server import run_daemon

    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one first.")
        return

    click.echo(f"Starting daemon on port {port}...")
    click.echo(f"Identity: {ident.identity_hash}")

    try:
        asyncio.run(run_daemon(
            identity=ident,
            storage=storage,
            port=port,
        ))
    except KeyboardInterrupt:
        click.echo("\nStopping daemon...")


@daemon.command("status")
def daemon_status():
    """Check daemon status."""
    # TODO: Implement proper status check
    click.echo("Daemon status check not implemented yet")
    click.echo("Try: nodetide daemon start --foreground")


# API commands


@cli.group()
def api():
    """API server commands."""
    pass


@api.command("start")
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", type=int, default=4557, help="Port to listen on")
@click.option("--public", is_flag=True, help="Bind to 0.0.0.0 (public access)")
@click.option("--db-path", type=click.Path(), help="Path to database file")
@click.option("--web-root", type=click.Path(exists=True), help="Path to web client files")
@click.option("--relay", is_flag=True, help="Run in relay mode (API only, no web interface)")
@click.option("--poll-interval", type=int, default=300, help="Polling interval in seconds (relay mode)")
@click.option("--mdns", is_flag=True, help="Enable mDNS announcement for local network discovery")
def api_start(host: str, port: int, public: bool, db_path: str | None, web_root: str | None, relay: bool, poll_interval: int, mdns: bool):
    """Start the REST API server.

    In relay mode (--relay), only the API is served without the web interface.
    This is suitable for home servers acting as distribution points.

    Examples:
      # Run with web interface (default)
      nodetide api start --public --web-root ./web

      # Run as relay (API only)
      nodetide api start --public --relay
    """
    import asyncio
    import logging
    import os
    from nodetide.api.app import run_api_server

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    if public:
        host = "0.0.0.0"
        click.echo("WARNING: Binding to 0.0.0.0 - API will be publicly accessible")

    # Relay mode disables web interface
    if relay:
        web_root = None
        os.environ["NODETIDE_RELAY_MODE"] = "1"
        click.echo(f"Running in RELAY mode (poll_interval={poll_interval}s)")

    # mDNS announcement
    if mdns:
        os.environ["NODETIDE_MDNS"] = "1"
        click.echo(f"mDNS announcement enabled (_nodetide._tcp.local.)")

    click.echo(f"Starting API server on http://{host}:{port}")
    if web_root:
        click.echo(f"Serving web client from {web_root}")
    click.echo("Endpoints:")
    click.echo("  GET  /health               - Health check")
    click.echo("  POST /api/identities       - Create identity")
    click.echo("  GET  /api/identities       - List identities")
    click.echo("  GET  /api/identities/{hash} - Get identity")
    click.echo("  POST /api/identities/{hash}/events - Submit event")
    click.echo("  POST /api/messages         - Publish message")
    click.echo("  GET  /api/messages         - List messages")
    if relay:
        click.echo("Relay endpoints:")
        click.echo("  GET  /api/relay/status     - Relay status")
        click.echo("  POST /api/relay/identities - Add identity to relay")
        click.echo("  GET  /api/relay/identities - List relayed identities")
        click.echo("  DELETE /api/relay/identities/{hash} - Remove from relay")
        click.echo("  POST /api/relay/polling/suspend - Suspend polling")
        click.echo("  POST /api/relay/polling/resume  - Resume polling")
        click.echo("  POST /api/relay/polling/trigger - Poll now")
        click.echo("  PUT  /api/relay/polling/interval - Set interval")
    click.echo("")

    try:
        asyncio.run(run_api_server(
            host=host,
            port=port,
            db_path=db_path,
            web_root=web_root,
            relay_mode=relay,
            poll_interval=poll_interval,
            mdns=mdns,
        ))
    except KeyboardInterrupt:
        click.echo("\nStopping API server...")


@api.command("docs")
def api_docs():
    """Show API documentation."""
    docs = """
Nodetide REST API
===================

IDENTITY ENDPOINTS
------------------

POST /identities
  Create identity with signed genesis event
  Body: {"event": {genesis event}}

GET /identities
  List known identities

GET /identities/{hash}
  Get identity details

GET /identities/{hash}/sigchain
  Get full sigchain

POST /identities/{hash}/events
  Submit a signed event
  Body: {"event": {signed event}}

GET /identities/{hash}/devices
  List active devices

SESSION ENDPOINTS
-----------------

POST /session
  Create session (requires signed request)
  Body: {"identity": "...", "device_pubkey": "...", "timestamp": ..., "signature": "..."}

GET /session
  Check session status (requires Bearer token)

DELETE /session
  Invalidate session

RECOVERY ENDPOINTS
------------------

POST /identities/{hash}/recovery/initiate
  Start recovery process
  Body: {"new_pubkey": "...", "new_encryption_pubkey": "...", "initiated_by": "..."}

POST /identities/{hash}/recovery/{id}/sign
  Submit trustee signature
  Body: {"trustee_identity": "...", "signature": "..."}

GET /identities/{hash}/recovery/{id}
  Check recovery status

GET /identities/{hash}/recovery/pending
  List pending recoveries

TRUST ENDPOINTS
---------------

POST /trust/delegations
  Create trust delegation (requires Bearer token)
  Body: {"delegation": {"from_identity", "to_identity", "weight", "scope"?, "depth_limit"?}}

GET /trust/delegations?from={hash}
  Get delegations from an identity

GET /trust/calculate/{hash}?claim_type=
  Trust in an attestation issuer via delegation paths (requires Bearer token)

QUERY ENDPOINTS
---------------

POST /verify
  Verify a sigchain
  Body: {"sigchain": [events]}

GET /lookup/{hash}
  Lookup identity
"""
    click.echo(docs)


# Relay commands


@cli.group()
def relay():
    """Relay discovery and management commands."""
    pass


@relay.command("discover")
@click.option("--timeout", "-t", type=int, default=5, help="Discovery timeout in seconds")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def relay_discover(timeout: int, as_json: bool):
    """Discover relay nodes on the local network via mDNS.

    Scans for nodetide relay nodes advertising via mDNS (_nodetide._tcp.local.)
    and displays their addresses.

    Examples:
      nodetide relay discover
      nodetide relay discover --timeout 10
      nodetide relay discover --json
    """
    import asyncio
    from nodetide.relay import RelayDiscovery

    relays_found = []

    def on_found(ip: str, port: int, props: dict):
        relays_found.append({"ip": ip, "port": port, "properties": props})
        if not as_json:
            click.echo(f"  Found: {ip}:{port}")

    async def discover():
        if not as_json:
            click.echo(f"Scanning for relays ({timeout}s)...")

        discovery = RelayDiscovery(on_found=on_found)
        await discovery.start()
        await asyncio.sleep(timeout)
        await discovery.stop()

    asyncio.run(discover())

    if as_json:
        import json
        click.echo(json.dumps(relays_found, indent=2))
    else:
        if not relays_found:
            click.echo("No relays found on the local network.")
        else:
            click.echo(f"\nFound {len(relays_found)} relay(s).")


@relay.command("connect")
@click.argument("url", required=False)
@click.option("--discover", "use_discover", is_flag=True, help="Discover and select a relay")
def relay_connect(url: str | None, use_discover: bool):
    """Set the relay URL for this client.

    The relay URL is used for syncing identities and messages.

    Examples:
      nodetide relay connect http://192.168.1.100:4557
      nodetide relay connect --discover
    """
    import asyncio
    from nodetide.relay import RelayDiscovery

    if use_discover:
        relays_found = []

        def on_found(ip: str, port: int, props: dict):
            relays_found.append((ip, port, props))

        async def discover():
            click.echo("Scanning for relays (3s)...")
            discovery = RelayDiscovery(on_found=on_found)
            await discovery.start()
            await asyncio.sleep(3)
            await discovery.stop()

        asyncio.run(discover())

        if not relays_found:
            click.echo("No relays found. Specify URL manually.")
            return

        if len(relays_found) == 1:
            ip, port, _ = relays_found[0]
            url = f"http://{ip}:{port}"
            click.echo(f"Found relay: {url}")
        else:
            click.echo("Found relays:")
            for i, (ip, port, props) in enumerate(relays_found):
                name = props.get("name", f"{ip}:{port}")
                click.echo(f"  [{i+1}] {name} - http://{ip}:{port}")

            choice = click.prompt("Select relay", type=int, default=1)
            if 1 <= choice <= len(relays_found):
                ip, port, _ = relays_found[choice - 1]
                url = f"http://{ip}:{port}"
            else:
                click.echo("Invalid selection.")
                return

    if not url:
        click.echo("Specify a relay URL or use --discover")
        return

    # Save relay URL to storage
    storage = get_storage()
    storage.set_relay_config("relay_url", url)
    storage.close()

    click.echo(f"Relay URL set to: {url}")


@relay.command("status")
def relay_status():
    """Show current relay configuration."""
    storage = get_storage()
    relay_url = storage.get_relay_config("relay_url")
    storage.close()

    if relay_url:
        click.echo(f"Relay URL: {relay_url}")

        # Try to fetch status
        import asyncio
        import aiohttp

        async def fetch_status():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{relay_url}/api/relay/status", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            click.echo(f"Status: connected")
                            click.echo(f"  Running: {data.get('running')}")
                            click.echo(f"  Suspended: {data.get('suspended')}")
                            click.echo(f"  Poll interval: {data.get('poll_interval')}s")
                            click.echo(f"  Identities: {data.get('identities_count', 0)}")
                        else:
                            click.echo(f"Status: error ({resp.status})")
            except Exception as e:
                click.echo(f"Status: unreachable ({e})")

        asyncio.run(fetch_status())
    else:
        click.echo("No relay configured. Use 'nodetide relay connect' to set one.")


# Group commands


@cli.group()
def group():
    """Group commands."""
    pass


@group.command("create")
@click.option("--name", "-n", required=True, help="Group name")
def group_create(name: str):
    """Create a new group."""
    from nodetide.messaging.group import GroupCreateEvent, Group

    storage = get_storage()
    ident = get_default_identity(storage)

    if not ident:
        click.echo("No default identity. Create one first.")
        return

    event = GroupCreateEvent.create(
        keypair=ident.local_keypair,
        creator_identity=ident.identity_hash,
        name=name,
    )

    grp = Group(events=[event])

    # Save group
    storage.close()  # TODO: implement group storage

    click.echo(f"Created group: {event.group_id}")
    click.echo(f"Name: {name}")


if __name__ == "__main__":
    cli()
