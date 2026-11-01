"""mDNS: what a node says on the LAN, which discovered nodes may be used as chain sources, and the fetcher using them."""

import asyncio
import ipaddress
import os

import pytest

from nodetide.core.identity import Identity, Sigchain
from nodetide.core.storage import Storage
from nodetide.oidc.fetcher import IdentityFetcher
from nodetide.relay.lan import LanSources, MAX_PEERS, acceptable_lan_ip
from nodetide.relay.mdns import MAX_IDS, parse_ids, txt_properties

NETS = [ipaddress.ip_network("192.168.1.0/24"), ipaddress.ip_network("10.0.0.0/16")]
OWN = {"192.168.1.10"}
H1, H2, H3, H4 = ("a1" * 32, "b2" * 32, "c3" * 32, "d4" * 32)


def test_the_announcement_lists_only_chosen_valid_identities_and_few():
    props = txt_properties([H1, "not-a-hash", H1, H2, H3, H4], scheme="https")
    assert props["version"] == "1" and props["path"] == "/api" and props["scheme"] == "https"
    assert props["ids"].split(",") == [H1, H2, H3] and len(props["ids"]) < 255 and MAX_IDS == 3
    assert "ids" not in txt_properties()
    assert txt_properties(scheme="gopher")["scheme"] == "http"
    assert parse_ids({"ids": f"{H1},zzz,{H2}"}) == [H1, H2] and parse_ids({}) == []


@pytest.mark.parametrize("ip,ok", [
    ("192.168.1.77", True), ("10.0.5.9", True),
    ("192.168.1.10", False),                      # ourselves
    ("192.168.2.5", False),                       # private, but not a network we are on
    ("127.0.0.1", False), ("169.254.169.254", False), ("0.0.0.0", False), ("224.0.0.251", False),
    ("8.8.8.8", False), ("fe80::1", False), ("garbage", False), ("", False),
])
def test_only_addresses_on_our_own_networks_are_used(ip, ok):
    assert acceptable_lan_ip(ip, NETS, OWN) is ok


class FakeDiscovery:
    def __init__(self, peers):
        self._peers = peers

    def peers(self):
        return self._peers

    async def start(self):
        pass

    async def stop(self):
        pass


def peer(ip, port=4557, scheme="http"):
    return {"name": f"n-{ip}", "ip": ip, "port": port, "scheme": scheme, "ids": [], "properties": {}}


def test_lan_sources_filters_and_caps():
    peers = [peer("192.168.1.20"), peer("192.168.1.20"), peer("8.8.8.8"), peer("169.254.169.254", 80), peer("192.168.1.21", 0),
             peer("192.168.1.22", scheme="javascript"), peer("192.168.1.10")] + [peer(f"10.0.0.{i}") for i in range(1, 20)]
    urls = LanSources(FakeDiscovery(peers), networks=lambda: (NETS, OWN)).urls()
    assert urls[:2] == ["http://192.168.1.20:4557", "http://192.168.1.22:4557"] and len(urls) == MAX_PEERS
    assert not any("8.8.8.8" in u or "169.254" in u or ":0" in u for u in urls)


def ahead():
    ident = Identity.create(name="Alice")
    old = Sigchain.from_list(ident.sigchain.to_list())
    ident.add_device("phone")
    return ident, old


async def test_the_fetcher_tries_lan_nodes_after_the_internet_and_takes_a_good_chain():
    ident, old = ahead()
    storage = Storage.memory()
    storage.save_sigchain(old)
    asked = []

    async def http(base, h):
        asked.append(("http", base))
        return None

    async def lan(base, h):
        asked.append(("lan", base))
        return ident.sigchain.to_list()

    fetcher = IdentityFetcher(storage, seed_nodes=["https://seed.example"], fetch=http, lan_fetch=lan)
    fetcher.lan = LanSources(FakeDiscovery([peer("192.168.1.20"), peer("8.8.8.8")]), networks=lambda: (NETS, OWN))
    fetcher.schedule(ident.identity_hash, want_head=ident.sigchain.head_hash)
    await fetcher.run_once()
    assert asked == [("http", "https://seed.example"), ("lan", "http://192.168.1.20:4557")]      # internet first; the outsider never asked
    assert storage.get_sigchain(ident.identity_hash).head_hash == ident.sigchain.head_hash
    assert fetcher.status(ident.identity_hash)["state"] == "done"


async def test_a_lan_node_cannot_plant_a_bad_chain_and_failures_are_tolerated():
    ident, old = ahead()
    storage = Storage.memory()
    storage.save_sigchain(old)
    events = ident.sigchain.to_list()
    events[1]["signature"] = "00" * 64

    async def http(base, h):
        return None

    calls = []

    async def lan(base, h):
        calls.append(base)
        if base.endswith(".20:4557"):
            raise ConnectionRefusedError()
        return events

    fetcher = IdentityFetcher(storage, fetch=http, lan_fetch=lan)
    fetcher.lan = LanSources(FakeDiscovery([peer("192.168.1.20"), peer("192.168.1.21")]), networks=lambda: (NETS, OWN))
    fetcher.schedule(ident.identity_hash, want_head=ident.sigchain.head_hash)
    await fetcher.run_once()
    assert len(calls) == 2 and storage.get_sigchain(ident.identity_hash).head_hash == old.head_hash
    assert fetcher.status(ident.identity_hash)["state"] == "pending"


async def test_without_lan_discovery_nothing_changes():
    ident, old = ahead()
    storage = Storage.memory()
    storage.save_sigchain(old)

    async def http(base, h):
        return None

    async def lan(base, h):
        raise AssertionError("must not be called")

    fetcher = IdentityFetcher(storage, fetch=http, lan_fetch=lan)
    fetcher.schedule(ident.identity_hash, want_head=ident.sigchain.head_hash)
    await fetcher.run_once()
    assert fetcher.status(ident.identity_hash)["attempts"] == 1


@pytest.mark.skipif(os.environ.get("NODETIDE_MDNS_TESTS") != "1", reason="needs multicast on this machine: NODETIDE_MDNS_TESTS=1")
async def test_announce_and_discover_on_this_machine():
    from nodetide.relay.mdns import RelayDiscovery, RelayMDNS
    found = []
    announcer = RelayMDNS(port=45999, name="nodetide-test-node", identities=[H1])
    discovery = RelayDiscovery(on_found=lambda ip, port, props: found.append((ip, port, props)))
    await discovery.start()
    await announcer.start()
    try:
        for _ in range(100):
            if any(p["port"] == 45999 for p in discovery.peers()):
                break
            await asyncio.sleep(0.1)
    finally:
        await announcer.stop()
        await discovery.stop()
    (mine,) = [p for p in discovery.peers() if p["port"] == 45999]
    assert mine["ids"] == [H1] and mine["scheme"] == "http" and mine["properties"]["path"] == "/api"
