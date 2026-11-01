"""Plain-text distribution points in TXT records: `v=nt1; id=...; dp=...`."""

import json

import pytest
from click.testing import CliRunner

from nodetide.core.dns_source import (
    DnsStateSource, MAX_PLAIN_POINTS, apex_name, parse_plain, plain_point_ok, plain_record, record_name,
)
from nodetide.core.identity import DeviceCapability, Identity, Sigchain
from nodetide.core.state import build_state, encode
from nodetide.core.storage import Storage
from nodetide.oidc.fetcher import IdentityFetcher

H = "ab" * 32
OTHER = "cd" * 32


def test_the_record_is_readable_and_leaves_out_what_cannot_be_written():
    text = plain_record(H, ["https://node.example.org", "mailto:chains@node.example.org", "dns:example.org", "has space", "semi;colon", "https://node.example.org", "dtn://x:4556"])
    assert text == f"v=nt1; id={H}; dp=https://node.example.org; dp=mailto:chains@node.example.org; dp=dtn://x:4556"
    assert plain_record(H, []) == f"v=nt1; id={H}"
    assert text.count("dp=") <= MAX_PLAIN_POINTS and len(plain_record(H, [f"https://n{i}.example.org" for i in range(30)]).split("dp=")) == MAX_PLAIN_POINTS + 1
    assert plain_point_ok("https://a.example") and not plain_point_ok("a b") and not plain_point_ok("a;b") and not plain_point_ok("é") and not plain_point_ok("")


def test_a_reader_takes_only_what_it_may_use():
    text = f"v=nt1; id={H}; dp=https://node.example.org; dp=mailto:chains@node.example.org; dp=ftp://x.example; dp=javascript:alert(1); dp=mailto:a@b.example?cc=v@c.example; dp=dtn://x:4556; dp=https://node.example.org"
    assert parse_plain(text) == {"id": H, "dp": ["https://node.example.org", "mailto:chains@node.example.org"]}
    # spacing is forgiving, unknown tags are ignored, tags are case-sensitive lower-case like SPF's
    assert parse_plain(f" v=nt1 ;id={H};  note=hello ; dp=http://192.168.1.5:4557 ;") == {"id": H, "dp": ["http://192.168.1.5:4557"]}


@pytest.mark.parametrize("text", [
    "", "v=spf1 -all", "nt1;abcdef", f"id={H}; dp=https://a.example", f"v=nt2; id={H}", f"v=nt1; dp=https://a.example", f"v=nt1; id=zz",
    f"v=nt1; id={H}; id={OTHER}", f"v=nt1; id={H.upper()}", f"v=nt1; id={H}; junk", f"v=nt1; id={H}; =x", None, 5, "v=nt1; id=" + H + "; dp=" + "a" * 2000,
])
def test_anything_else_is_not_a_plain_record(text):
    assert parse_plain(text) is None


def test_the_signed_state_and_the_plain_list_live_side_by_side():
    ident = Identity.create(name="Alice", distribution_points=["https://node.example.org", "dns:example.org"])
    ident.add_device("phone", capabilities=[DeviceCapability.AUTHENTICATE])
    name = record_name("example.org", ident.identity_hash)
    plain = plain_record(ident.identity_hash, ["https://node.example.org", "dns:example.org"])
    state = encode(build_state(ident.sigchain, ident.local_keypair))

    async def run():
        async def lookup(n):
            return {name: ["v=spf1 -all", plain, state, plain_record(OTHER, ["https://evil.example"])]}.get(n, [])
        source = DnsStateSource(lookup=lookup)
        assert await source.points("example.org", ident.identity_hash) == ["https://node.example.org"]
        assert (await source.fetch("example.org", ident.identity_hash)).identity_hash == ident.identity_hash
        assert await source.points("example.org", OTHER) == []                        # another identity's record at this name is not ours
        assert await source.points("localhost", ident.identity_hash) == [] and await source.points("example.org", "zz") == []
    import asyncio
    asyncio.run(run())


async def test_a_domain_lists_the_identities_it_hosts():
    names = {apex_name("example.org"): [plain_record(H, ["https://a.example.org"]), plain_record(OTHER, ["mailto:chains@a.example.org"]),
                                        plain_record(H, ["https://b.example.org"]), "v=spf1 -all"]}

    async def lookup(n):
        return names.get(n, [])
    found = await DnsStateSource(lookup=lookup).discover("example.org")
    assert found == [{"id": H, "dp": ["https://a.example.org", "https://b.example.org"]}, {"id": OTHER, "dp": ["mailto:chains@a.example.org"]}]
    assert await DnsStateSource(lookup=lookup).discover("not a domain") == []


# --- the fetcher ------------------------------------------------------------------------------------------------------

def behind():
    ident = Identity.create(name="Alice", distribution_points=["dns:example.org"])
    old = Sigchain.from_list(ident.sigchain.to_list())
    ident.add_device("phone")
    return ident, old


async def test_the_fetcher_looks_where_dns_says():
    ident, old = behind()
    storage = Storage.memory()
    storage.save_sigchain(old)
    asked = []

    async def http(base, h):
        asked.append(base)
        return ident.sigchain.to_list() if base == "https://node.example.org" else None

    async def lookup(n):
        if n == record_name("example.org", ident.identity_hash):
            return [plain_record(ident.identity_hash, ["http://127.0.0.1:4557", "http://192.168.1.5:4557", "https://node.example.org"])]
        return []

    fetcher = IdentityFetcher(storage, fetch=http)
    fetcher.dns = DnsStateSource(lookup=lookup)
    fetcher.schedule(ident.identity_hash, want_head=ident.sigchain.head_hash)
    await fetcher.run_once()
    assert asked == ["https://node.example.org"]                                # loopback and LAN addresses from DNS are not used
    assert storage.get_sigchain(ident.identity_hash).head_hash == ident.sigchain.head_hash


async def test_dns_is_not_asked_for_an_identity_that_names_no_domain_and_a_failing_resolver_is_harmless():
    ident = Identity.create(name="NoDomain", distribution_points=["https://dead.example"])
    storage = Storage.memory()
    storage.save_sigchain(ident.sigchain)
    calls = []

    async def lookup(n):
        calls.append(n)
        raise OSError("down")

    async def http(base, h):
        return None

    fetcher = IdentityFetcher(storage, fetch=http)
    fetcher.dns = DnsStateSource(lookup=lookup)
    fetcher.schedule(ident.identity_hash, hints=["https://hint.example"], want_head="ab" * 32)
    await fetcher.run_once()
    assert calls == []                                                           # nothing in the chain points at DNS
    ident2, old = behind()
    storage.save_sigchain(old)
    fetcher.schedule(ident2.identity_hash, want_head=ident2.sigchain.head_hash)
    assert await fetcher.run_once() >= 1 and calls                               # asked, failed, carried on
    assert fetcher.status(ident2.identity_hash)["attempts"] == 1


async def test_mailboxes_listed_in_dns_are_used_for_the_email_fallback():
    from nodetide.mailresponder.fetch import MailFetchService
    from nodetide.verifiers.mail import MemorySender
    ident, old = behind()
    storage = Storage.memory()
    storage.save_sigchain(old)

    async def http(base, h):
        return None

    async def lookup(n):
        return [plain_record(ident.identity_hash, ["mailto:chains@remote.example"])] if n == record_name("example.org", ident.identity_hash) else []

    out = MemorySender()
    fetcher = IdentityFetcher(storage, fetch=http)
    fetcher.dns = DnsStateSource(lookup=lookup)
    fetcher.mail = MailFetchService(out, "chains@ours.example", deliver=fetcher.deliver)
    fetcher.schedule(ident.identity_hash, want_head=ident.sigchain.head_hash)
    await fetcher.run_once()
    assert [m["To"] for m in out.messages] == ["chains@remote.example"]


# --- CLI ------------------------------------------------------------------------------------------------------------------

def test_the_cli_prints_the_plain_record_and_looks_things_up(tmp_path, monkeypatch):
    from nodetide.cli.main import cli
    monkeypatch.setenv("NODETIDE_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(cli, ["identity", "create", "-n", "Alice"]).exit_code == 0
    assert runner.invoke(cli, ["identity", "set-distribution", "-d", "dns:example.org", "-d", "https://node.example.org", "-d", "mailto:chains@node.example.org"]).exit_code == 0
    out = runner.invoke(cli, ["identity", "dns-record"])
    assert out.exit_code == 0, out.output
    storage = Storage.open(tmp_path / "nodetide.db")
    me = storage.get_default_identity().identity_hash
    storage.close()
    plain = f"v=nt1; id={me}; dp=https://node.example.org; dp=mailto:chains@node.example.org"
    assert f'Value: "{plain}"' in out.output and f"_nodetide.example.org" in out.output
    assert out.output.count(f'"{plain}"') == 2                                    # at the identity's name and at the domain's
    data = json.loads(runner.invoke(cli, ["identity", "dns-record", "--json"]).output)
    assert data["plain"]["value"] == plain and data["discovery"]["name"] == "_nodetide.example.org"

    async def lookup(n):
        return {apex_name("example.org"): [plain], record_name("example.org", me): [plain]}.get(n, [])
    monkeypatch.setattr("nodetide.core.dns_source.DnsStateSource", lambda: DnsStateSource(lookup=lookup))
    shown = runner.invoke(cli, ["identity", "dns-lookup", "example.org", me])
    assert shown.exit_code == 0, shown.output
    assert me in shown.output and "https://node.example.org" in shown.output and "signed state: none" in shown.output
    assert runner.invoke(cli, ["identity", "dns-lookup", "192.168.1.5"]).exit_code != 0
