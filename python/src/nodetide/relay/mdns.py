"""mDNS service announcement for nodetide relay."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Callable

from zeroconf import IPVersion, ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

logger = logging.getLogger(__name__)

# Service type for nodetide relay
SERVICE_TYPE = "_nodetide._tcp.local."
SERVICE_NAME = "Nodetide Relay._nodetide._tcp.local."


MAX_IDS = 3          # a TXT record is small; this many 64-hex identity hashes fit with room to spare
_HASH = __import__("re").compile(r"^[0-9a-f]{64}$")


def txt_properties(identities: "list[str] | tuple[str, ...]" = (), scheme: str = "http", extra: "dict[str, str] | None" = None) -> dict[str, str]:
    """What a node says about itself on the LAN. `ids` lists identities the operator chose to advertise (never all of them:
    everybody on the network can read this); a client that wants *its* node looks for its own hash here."""
    props = {"version": "1", "path": "/api", "scheme": scheme if scheme in ("http", "https") else "http"}
    ids = [h for h in dict.fromkeys(identities) if isinstance(h, str) and _HASH.match(h)][:MAX_IDS]
    if ids:
        props["ids"] = ",".join(ids)
    props.update(extra or {})
    return props


def parse_ids(props: "dict[str, str]") -> list[str]:
    """The identity hashes a discovered node advertises (valid ones only)."""
    return [h for h in str(props.get("ids", "")).split(",") if _HASH.match(h)][:MAX_IDS]


def get_local_ip() -> str:
    """Get the local IP address."""
    try:
        # Create a socket to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class RelayMDNS:
    """mDNS service announcement for relay nodes."""

    def __init__(
        self,
        port: int = 4557,
        name: str | None = None,
        properties: dict[str, str] | None = None,
        identities: "list[str] | tuple[str, ...]" = (),
        scheme: str = "http",
    ):
        """Initialize mDNS announcement.

        Args:
            port: The port the relay is running on
            name: Optional service name (defaults to hostname)
            properties: Optional TXT record properties
        """
        self.port = port
        self.name = name or socket.gethostname()
        self.properties = txt_properties(identities, scheme, properties)
        self._zeroconf: AsyncZeroconf | None = None
        self._service_info: ServiceInfo | None = None

    async def start(self) -> None:
        """Start announcing the relay service."""
        if self._zeroconf:
            return

        local_ip = get_local_ip()

        props = dict(self.properties)

        # Create service info
        service_name = f"{self.name}.{SERVICE_TYPE}"
        self._service_info = ServiceInfo(
            SERVICE_TYPE,
            service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=props,
            server=f"{self.name}.local.",
        )

        # Start zeroconf
        self._zeroconf = AsyncZeroconf(ip_version=IPVersion.V4Only)
        await self._zeroconf.async_register_service(self._service_info)

        logger.info(f"mDNS: Announcing {service_name} at {local_ip}:{self.port}")

    async def stop(self) -> None:
        """Stop announcing the relay service."""
        if self._zeroconf and self._service_info:
            await self._zeroconf.async_unregister_service(self._service_info)
            await self._zeroconf.async_close()
            self._zeroconf = None
            self._service_info = None
            logger.info("mDNS: Service unregistered")

    async def update_properties(self, properties: dict[str, str]) -> None:
        """Update service properties."""
        if not self._zeroconf or not self._service_info:
            return

        self.properties.update(properties)
        props = dict(self.properties)

        # Update service info
        self._service_info.properties = props
        await self._zeroconf.async_update_service(self._service_info)
        logger.debug(f"mDNS: Updated properties")


class RelayDiscovery:
    """Discover nodetide relay nodes on the local network."""

    def __init__(self, on_found: Callable[[str, int, dict], None] | None = None):
        """Initialize relay discovery.

        Args:
            on_found: Callback when a relay is found (ip, port, properties)
        """
        self.on_found = on_found
        self._zeroconf: AsyncZeroconf | None = None
        self._browser = None
        self._relays: dict[str, tuple[str, int, dict]] = {}

    async def start(self) -> None:
        """Start discovering relay nodes."""
        from zeroconf.asyncio import AsyncServiceBrowser

        if self._zeroconf:
            return

        self._zeroconf = AsyncZeroconf(ip_version=IPVersion.V4Only)

        class Handler:
            def __init__(handler_self):
                handler_self.discovery = self

            def add_service(handler_self, zc, service_type, name):
                asyncio.create_task(handler_self._handle_add(zc, service_type, name))

            def remove_service(handler_self, zc, service_type, name):
                if name in handler_self.discovery._relays:
                    del handler_self.discovery._relays[name]
                    logger.debug(f"mDNS: Relay removed: {name}")

            def update_service(handler_self, zc, service_type, name):
                asyncio.create_task(handler_self._handle_add(zc, service_type, name))

            async def _handle_add(handler_self, zc, service_type, name):
                info = await self._zeroconf.async_get_service_info(service_type, name)
                if info:
                    addresses = info.parsed_addresses()
                    if addresses:
                        ip = addresses[0]
                        port = info.port
                        props = {
                            k.decode() if isinstance(k, bytes) else k:
                            v.decode() if isinstance(v, bytes) else v
                            for k, v in (info.properties or {}).items()
                        }

                        handler_self.discovery._relays[name] = (ip, port, props)
                        logger.debug(f"mDNS: Found relay {name} at {ip}:{port}")

                        if handler_self.discovery.on_found:
                            handler_self.discovery.on_found(ip, port, props)

        self._browser = AsyncServiceBrowser(
            self._zeroconf.zeroconf,
            SERVICE_TYPE,
            Handler(),
        )

        logger.info("mDNS: Started relay discovery")

    async def stop(self) -> None:
        """Stop discovering relay nodes."""
        if self._browser:
            await self._browser.async_cancel()
            self._browser = None

        if self._zeroconf:
            await self._zeroconf.async_close()
            self._zeroconf = None

        logger.info("mDNS: Stopped relay discovery")

    def peers(self) -> list[dict]:
        """Discovered nodes as dicts: name, ip, port, scheme, ids, properties (announcements of a wrong version are skipped)."""
        out = []
        for name, (ip, port, props) in self._relays.items():
            if props.get("version") != "1":
                continue
            out.append({"name": name, "ip": ip, "port": port, "scheme": props.get("scheme", "http"),
                        "ids": parse_ids(props), "properties": props})
        return out

    def get_relays(self) -> list[tuple[str, int, dict]]:
        """Get list of discovered relays.

        Returns:
            List of (ip, port, properties) tuples
        """
        return list(self._relays.values())
