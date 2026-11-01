"""Nodes found on the local network as a last-resort source of sigchains.

Discovery by multicast is unauthenticated: anybody on the LAN can announce a node. That is acceptable because a chain
verifies itself (a fake node can only withhold data or see which identity is asked for), but we must not let an
announcement aim our requests at arbitrary hosts. So only an address on a network *we are attached to* is used, never our
own, never loopback or the cloud metadata address, and we only ever send `GET /api/identities/<hash>/sigchain` to it.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Callable

logger = logging.getLogger(__name__)

MAX_PEERS = 8
_NEVER = [ipaddress.ip_network("169.254.169.254/32"), ipaddress.ip_network("0.0.0.0/8"), ipaddress.ip_network("127.0.0.0/8"),
          ipaddress.ip_network("224.0.0.0/4"), ipaddress.ip_network("255.255.255.255/32")]


def local_networks() -> tuple[list[ipaddress.IPv4Network], set[str]]:
    """The IPv4 networks of this machine's interfaces, and its own addresses."""
    import ifaddr
    networks: list[ipaddress.IPv4Network] = []
    own: set[str] = set()
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            if isinstance(ip.ip, str):
                own.add(ip.ip)
                try:
                    net = ipaddress.ip_network(f"{ip.ip}/{ip.network_prefix}", strict=False)
                except ValueError:
                    continue
                if net.version == 4 and not net.is_loopback and net.prefixlen >= 8:
                    networks.append(net)
    return networks, own


def acceptable_lan_ip(ip: str, networks: list[ipaddress.IPv4Network], own: set[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4 or ip in own or any(addr in n for n in _NEVER):
        return False
    return any(addr in n for n in networks)


class LanSources:
    """Turns the discovery results into base URLs the fetcher may try."""

    def __init__(self, discovery, networks: Callable[[], "tuple[list, set[str]]"] = local_networks):
        self.discovery, self._networks = discovery, networks

    async def start(self) -> None:
        await self.discovery.start()

    async def stop(self) -> None:
        await self.discovery.stop()

    def urls(self) -> list[str]:
        networks, own = self._networks()
        out: list[str] = []
        for peer in self.discovery.peers():
            port = peer["port"]
            if not isinstance(port, int) or not 1 <= port <= 65535:
                continue
            if not acceptable_lan_ip(peer["ip"], networks, own):
                logger.debug("mDNS: ignoring a node at an address outside our networks")
                continue
            url = f"{peer['scheme'] if peer['scheme'] in ('http', 'https') else 'http'}://{peer['ip']}:{port}"
            if url not in out:
                out.append(url)
        return out[:MAX_PEERS]
