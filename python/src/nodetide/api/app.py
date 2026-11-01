"""API application factory."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from aiohttp import web

from nodetide.core.storage import Storage
from nodetide.oidc import OIDCConfig, setup_oidc
from nodetide.oidc.fetcher import FetchFn
from nodetide.explorer import explorer_enabled, setup_explorer_api, setup_explorer_ui
from nodetide.eidas.verify import EidasPolicy, policy_from_env as eidas_policy_from_env, register as register_eidas
from nodetide.api.routes import setup_routes
from nodetide.api.auth import (
    ChallengeStore,
    SessionStore,
    RecoveryStore,
    setup_casbin_auth,
    casbin_middleware,
)


logger = logging.getLogger(__name__)


async def health_handler(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({
        "status": "healthy",
        "service": "nodetide",
        "commit": os.environ.get("GIT_COMMIT", "dev"),
    })


async def cleanup_task(app: web.Application) -> None:
    """Background task to cleanup expired sessions and recoveries."""
    session_store: SessionStore = app["session_store"]
    recovery_store: RecoveryStore = app["recovery_store"]
    challenge_store: ChallengeStore = app["challenge_store"]

    while True:
        await asyncio.sleep(60)  # Run every minute

        sessions_cleaned = session_store.cleanup_expired()
        recoveries_cleaned = recovery_store.cleanup_expired()
        challenges_cleaned = challenge_store.cleanup_expired()

        if sessions_cleaned or recoveries_cleaned or challenges_cleaned:
            logger.debug(
                f"Cleanup: {sessions_cleaned} sessions, {recoveries_cleaned} recoveries, "
                f"{challenges_cleaned} challenges"
            )


async def on_startup(app: web.Application) -> None:
    """Called on application startup."""
    app["cleanup_task"] = asyncio.create_task(cleanup_task(app))

    # Start relay poller if in relay mode
    if app.get("relay_poller"):
        await app["relay_poller"].start()

    # Start mDNS announcement if enabled
    if app.get("relay_mdns"):
        await app["relay_mdns"].start()

    logger.info("API server started")


async def on_cleanup(app: web.Application) -> None:
    """Called on application cleanup."""
    # Stop mDNS announcement
    if app.get("relay_mdns"):
        await app["relay_mdns"].stop()

    # Stop relay poller
    if app.get("relay_poller"):
        await app["relay_poller"].stop()

    if "cleanup_task" in app:
        app["cleanup_task"].cancel()
        try:
            await app["cleanup_task"]
        except asyncio.CancelledError:
            pass

    if "storage" in app:
        app["storage"].close()

    logger.info("API server stopped")


def create_app(
    storage: Storage | None = None,
    db_path: Path | str | None = None,
    web_root: Path | str | None = None,
    relay_mode: bool = False,
    poll_interval: int = 300,
    mdns: bool = False,
    port: int = 4557,
    auth_audience: str | None = None,
    oidc_config: OIDCConfig | None = None,
    oidc_fetch: FetchFn | None = None,
    eidas_policy: EidasPolicy | None = None,
) -> web.Application:
    """Create the API application.

    Args:
        storage: Existing storage instance to use
        db_path: Path to database file (if storage not provided)
        web_root: Path to web client files (optional)
        relay_mode: Enable relay mode with polling
        poll_interval: Polling interval in seconds (default 300)
        mdns: Enable mDNS announcement for relay discovery
        port: Port number for mDNS announcement
        auth_audience: Origin this node accepts logins for (or NODETIDE_AUTH_AUDIENCE)
        oidc_config: Enable the OIDC bridge (default: from NODETIDE_OIDC_* environment)
        oidc_fetch: Override how the bridge fetches unknown identities (tests)
        eidas_policy: Accept eIDAS qualified-signature proofs (default: NODETIDE_EIDAS_ANCHORS)

    Returns:
        Configured aiohttp Application
    """
    app = web.Application()

    # Setup storage
    if storage:
        app["storage"] = storage
    elif db_path:
        app["storage"] = Storage.open(Path(db_path))
    else:
        # Check environment variable or use default
        env_db_path = os.environ.get("NODETIDE_DB_PATH")
        if env_db_path:
            app["storage"] = Storage.open(Path(env_db_path))
        else:
            data_dir = Path.home() / ".nodetide"
            app["storage"] = Storage.open(data_dir / "nodetide.db")

    # Setup stores
    app["session_store"] = SessionStore()
    app["recovery_store"] = RecoveryStore()
    app["challenge_store"] = ChallengeStore()

    # Origin this node authenticates users for (native SSO login). Required for
    # POST /api/auth/login; challenges for other audiences are still allowed.
    app["auth_audience"] = auth_audience or os.environ.get("NODETIDE_AUTH_AUDIENCE")

    # Setup relay poller if in relay mode
    relay_mode = relay_mode or os.environ.get("NODETIDE_RELAY_MODE") == "1"
    if relay_mode:
        from nodetide.relay import RelayPoller
        app["relay_poller"] = RelayPoller(
            storage=app["storage"],
            poll_interval=poll_interval,
        )
        logger.info(f"Relay mode enabled (poll_interval={poll_interval}s)")

    # Setup mDNS announcement if enabled
    mdns = mdns or os.environ.get("NODETIDE_MDNS") == "1"
    if mdns:
        from nodetide.relay import RelayMDNS
        app["relay_mdns"] = RelayMDNS(port=port)
        logger.info(f"mDNS announcement enabled (port={port})")

    # Health check endpoint
    app.router.add_get("/health", health_handler)

    # Setup API routes
    setup_routes(app)

    # eIDAS qualified-signature proofs, judged against operator-supplied trust anchors.
    if eidas_policy is None:
        eidas_policy = eidas_policy_from_env()
    if eidas_policy is not None:
        register_eidas(eidas_policy)
        app["eidas_policy"] = eidas_policy
        logger.info(f"eIDAS proof verification enabled ({len(eidas_policy.store.anchors)} trust anchors)")

    # Explorer: read-only browsing of public information. The API is served in
    # every mode (including relay); the UI whenever a web root is configured.
    if explorer_enabled():
        setup_explorer_api(app)
        explorer_web_root = web_root or os.environ.get("NODETIDE_WEB_ROOT")
        if explorer_web_root and setup_explorer_ui(app, explorer_web_root):
            logger.info("Explorer UI available at /explorer")

    # OIDC bridge (registered before on_cleanup below so its fetcher stops
    # before storage is closed)
    if oidc_config is None:
        db_file = app["storage"].db_path
        key_dir = None if db_file.name == ":memory:" else db_file.parent
        oidc_config = OIDCConfig.from_env(default_key_dir=key_dir)
    if oidc_config is not None:
        setup_oidc(app, oidc_config, app["storage"], fetch=oidc_fetch)
        logger.info(f"OIDC bridge enabled (issuer={oidc_config.issuer})")

    # Setup lifecycle hooks
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # Add CORS middleware for browser clients
    @web.middleware
    async def cors_middleware(request: web.Request, handler) -> web.Response:
        if request.method == "OPTIONS":
            response = web.Response()
        else:
            response = await handler(request)

        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response

    app.middlewares.append(cors_middleware)

    # Setup casbin authorization (for relay mode, enforce access control)
    if relay_mode:
        setup_casbin_auth(app)
        app.middlewares.append(casbin_middleware)
        logger.info("Casbin authorization enabled")

    # Setup static file serving for web client (unless in relay mode)
    relay_mode = os.environ.get("NODETIDE_RELAY_MODE") == "1"
    resolved_web_root = None if relay_mode else (web_root or os.environ.get("NODETIDE_WEB_ROOT"))
    if resolved_web_root:
        web_path = Path(resolved_web_root)
        if web_path.exists():
            logger.info(f"Serving web client from {web_path}")

            # Serve index.html for root
            async def index_handler(request: web.Request) -> web.FileResponse:
                return web.FileResponse(web_path / "index.html")

            app.router.add_get("/", index_handler)
            # the node's sign-in page opens "<wallet>/signin?link=<challenge url>": the client reads it itself
            app.router.add_get("/signin", index_handler)

            # Serve specific static directories
            if (web_path / "js").exists():
                app.router.add_static("/js/", web_path / "js", name="js")

            # Serve root-level files (manifest, service worker, favicons)
            root_files = [
                "manifest.json",
                "sw.js",
                "favicon.svg",
                "favicon.ico",
                "favicon-16x16.png",
                "favicon-32x32.png",
                "favicon-192x192.png",
                "favicon-512x512.png",
                "apple-touch-icon.png",
                "android-chrome-192x192.png",
                "android-chrome-512x512.png",
            ]

            for filename in root_files:
                file_path = web_path / filename
                if file_path.exists():
                    # Create handler with closure to capture file_path
                    def make_handler(fp: Path):
                        async def handler(request: web.Request) -> web.FileResponse:
                            return web.FileResponse(fp)
                        return handler
                    app.router.add_get(f"/{filename}", make_handler(file_path))

    return app


async def run_api_server(
    host: str = "127.0.0.1",
    port: int = 4557,
    storage: Storage | None = None,
    db_path: Path | str | None = None,
    web_root: Path | str | None = None,
    relay_mode: bool = False,
    poll_interval: int = 300,
    mdns: bool = False,
) -> None:
    """Run the API server.

    Args:
        host: Host to bind to
        port: Port to listen on
        storage: Existing storage instance
        db_path: Path to database file
        web_root: Path to web client files
        relay_mode: Enable relay mode with polling
        poll_interval: Polling interval in seconds
        mdns: Enable mDNS announcement
    """
    app = create_app(
        storage=storage,
        db_path=db_path,
        web_root=web_root,
        relay_mode=relay_mode,
        poll_interval=poll_interval,
        mdns=mdns,
        port=port,
    )

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, host, port)
    await site.start()

    logger.info(f"API server running on http://{host}:{port}")

    # Keep running
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()
