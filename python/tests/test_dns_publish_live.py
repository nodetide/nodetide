"""Publishing against a real BIND (in Docker) with a TSIG key, and through a real acme.sh sourcing a plugin.

Opt-in, because they need Docker, nsupdate and (for the second) an acme.sh checkout:
    NODETIDE_DNS_TESTS=1 [NODETIDE_ACME_SH=/path/to/acme.sh] pytest tests/test_dns_publish_live.py
"""

import asyncio
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nodetide.core.dns_source import DnsStateSource, apex_name, plain_record, record_name
from nodetide.core.storage import Storage
from nodetide.dnspublish.publish import authoritative_lookup

PORT = 15353
IMAGE = "internetsystemsconsortium/bind9:9.20"
NAME = "nodetide-test-bind"

pytestmark = pytest.mark.skipif(
    os.environ.get("NODETIDE_DNS_TESTS") != "1" or not shutil.which("docker") or not shutil.which("nsupdate"),
    reason="set NODETIDE_DNS_TESTS=1 and have docker and nsupdate",
)

ZONE = """$TTL 300
@ IN SOA ns1.example.org. admin.example.org. 1 3600 600 86400 300
@ IN NS ns1.example.org.
ns1 IN A 127.0.0.1
_nodetide IN TXT "foreign entry that must survive"
"""


@pytest.fixture(scope="module")
def bind():
    base = Path(tempfile.mkdtemp())
    conf, cache = base / "conf", base / "cache"
    conf.mkdir()
    cache.mkdir()
    os.chmod(cache, 0o777)
    key = subprocess.run(["docker", "run", "--rm", "--entrypoint", "tsig-keygen", IMAGE, "-a", "hmac-sha256", "nt-key"],
                         capture_output=True, text=True, check=True).stdout
    (conf / "nt.key").write_text(key)
    (conf / "named.conf").write_text("""include "/etc/bind/nt.key";
options { directory "/var/cache/bind"; listen-on port 53 { any; }; listen-on-v6 { none; }; recursion no; allow-query { any; }; dnssec-validation no; };
zone "example.org" { type primary; file "/var/cache/bind/example.org.db"; allow-update { key "nt-key"; }; };
""")
    (cache / "example.org.db").write_text(ZONE)
    os.chmod(cache / "example.org.db", 0o666)
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", NAME, "-p", f"{PORT}:53/tcp", "-p", f"{PORT}:53/udp",
                    "-v", f"{conf}:/etc/bind:ro", "-v", f"{cache}:/var/cache/bind", IMAGE, "-g", "-c", "/etc/bind/named.conf"],
                   check=True, capture_output=True)
    lookup = authoritative_lookup("127.0.0.1", PORT)
    for _ in range(100):
        if asyncio.run(lookup("_nodetide.example.org")):
            break
        time.sleep(0.5)
    else:
        logs = subprocess.run(["docker", "logs", NAME], capture_output=True, text=True)
        pytest.fail("BIND did not come up: " + (logs.stdout + logs.stderr)[-800:])
    yield {"key": str(conf / "nt.key"), "lookup": lookup, "dir": base}
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)


@pytest.fixture
def me(tmp_path, monkeypatch):
    from nodetide.cli.main import cli
    monkeypatch.setenv("NODETIDE_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(cli, ["identity", "create", "-n", "Alice"]).exit_code == 0
    assert runner.invoke(cli, ["identity", "set-distribution", "-d", "dns:example.org", "-d", "https://node.example.org", "-d", "mailto:chains@node.example.org"]).exit_code == 0
    storage = Storage.open(tmp_path / "nodetide.db")
    ident = storage.get_default_identity().identity_hash
    storage.close()
    return cli, runner, ident


def publish(runner, cli, bind, *extra):
    return runner.invoke(cli, ["identity", "dns-publish", "--method", "nsupdate", "--nsupdate-server", "127.0.0.1", "--nsupdate-port", str(PORT),
                               "--nsupdate-key-file", bind["key"], "--zone", "example.org", *extra])


def test_publish_update_and_remove_with_a_real_name_server(bind, me):
    cli, runner, identity = me
    source = DnsStateSource(lookup=bind["lookup"], clock=lambda: time.time() + 10_000)       # a fresh cache each time: advance the clock

    def look():
        nonlocal source
        source = DnsStateSource(lookup=bind["lookup"])
        return source

    # first publication
    out = publish(runner, cli, bind)
    assert out.exit_code == 0, out.output
    assert out.output.count("  add ") == 3 and "Done." in out.output
    s = look()
    state = asyncio.run(s.fetch("example.org", identity))
    assert state is not None and state.identity_hash == identity and state.length == 2      # genesis, set_distribution
    assert asyncio.run(s.points("example.org", identity)) == ["https://node.example.org", "mailto:chains@node.example.org"]
    found = asyncio.run(look().discover("example.org"))
    assert [e["id"] for e in found] == [identity]
    assert asyncio.run(bind["lookup"]("_nodetide.example.org")).count("foreign entry that must survive") == 1       # untouched

    # nothing changed: nothing to do
    again = publish(runner, cli, bind)
    assert again.exit_code == 0 and "Nothing to change." in again.output

    # a new device and new points: the old state and plain list are replaced, there is still exactly one of each
    assert runner.invoke(cli, ["identity", "add-device", "--label", "phone"]).exit_code == 0
    assert runner.invoke(cli, ["identity", "set-distribution", "-d", "dns:example.org", "-d", "https://other.example.org"]).exit_code == 0
    third = publish(runner, cli, bind)
    assert third.exit_code == 0, third.output
    assert third.output.count("  remove ") == 3 and third.output.count("  add ") == 3
    values = asyncio.run(bind["lookup"](record_name("example.org", identity)))
    assert len(values) == 2 and sum(v.startswith("nt1;") for v in values) == 1
    s = look()
    assert asyncio.run(s.fetch("example.org", identity)).length == 4 and asyncio.run(s.points("example.org", identity)) == ["https://other.example.org"]
    assert asyncio.run(bind["lookup"]("_nodetide.example.org")).count("foreign entry that must survive") == 1

    # someone else's entry for another identity at the domain's name is left alone too
    other = plain_record("cd" * 32, ["https://theirs.example.org"])
    subprocess.run(["nsupdate", "-v", "-p", str(PORT), "-k", bind["key"]], input=f'server 127.0.0.1\nzone example.org.\nupdate add _nodetide.example.org. 300 TXT "{other}"\nsend\n',
                   text=True, check=True)
    assert publish(runner, cli, bind).exit_code == 0
    assert other in asyncio.run(bind["lookup"]("_nodetide.example.org"))

    # take it down: ours goes, theirs stays
    gone = publish(runner, cli, bind, "--remove")
    assert gone.exit_code == 0, gone.output
    assert asyncio.run(bind["lookup"](record_name("example.org", identity))) == []
    left = asyncio.run(bind["lookup"]("_nodetide.example.org"))
    assert other in left and "foreign entry that must survive" in left and not any(identity in v for v in left)


def test_a_wrong_key_is_refused_with_a_reason(bind, me, tmp_path):
    cli, runner, _ = me
    bad = tmp_path / "bad.key"
    bad.write_text('key "nt-key" { algorithm hmac-sha256; secret "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; };\n')
    out = runner.invoke(cli, ["identity", "dns-publish", "--method", "nsupdate", "--nsupdate-server", "127.0.0.1", "--nsupdate-port", str(PORT),
                              "--nsupdate-key-file", str(bad), "--zone", "example.org"])
    assert out.exit_code != 0 and "nsupdate failed" in out.output


@pytest.mark.skipif(not os.environ.get("NODETIDE_ACME_SH"), reason="set NODETIDE_ACME_SH to an acme.sh file to try the real plugin loader")
def test_a_plugin_is_run_by_the_real_acme_sh(me, tmp_path, monkeypatch):
    """The real acme.sh is sourced as a library, a plugin (a tiny fake provider) is called, credentials arrive from the environment."""
    cli, runner, identity = me
    home = tmp_path / "acme"
    (home / "dnsapi").mkdir(parents=True)
    shutil.copy(os.environ["NODETIDE_ACME_SH"], home / "acme.sh")
    log = tmp_path / "provider.log"
    (home / "dnsapi" / "dns_fake.sh").write_text('''#!/usr/bin/env sh
dns_fake_info='Fake provider
Options:
 FAKE_Token API token
'
dns_fake_add() {
  fulldomain="$(_idn "$1")"
  txtvalue=$2
  FAKE_Token="${FAKE_Token:-$(_readaccountconf_mutable FAKE_Token)}"
  [ -n "$FAKE_Token" ] || { _err "no FAKE_Token"; return 1; }
  _saveaccountconf_mutable FAKE_Token "$FAKE_Token"
  printf 'add\\t%s\\t%s\\n' "$fulldomain" "$txtvalue" >> "$FAKE_LOG"
}
dns_fake_rm() {
  printf 'rm\\t%s\\t%s\\n' "$(_idn "$1")" "$2" >> "$FAKE_LOG"
}
''')
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.delenv("FAKE_Token", raising=False)

    async def nothing(name):
        return []
    monkeypatch.setattr("nodetide.core.dns_source.system_txt_lookup", nothing)
    args = ["identity", "dns-publish", "--method", "acme", "--acme-plugin", "dns_fake", "--acme-home", str(home)]
    without = runner.invoke(cli, args)
    assert without.exit_code != 0 and "no FAKE_Token" in without.output                      # the plugin's own message comes through

    monkeypatch.setenv("FAKE_Token", "secret-token")
    ok = runner.invoke(cli, args)
    assert ok.exit_code == 0, ok.output
    rows = [l.split("\t") for l in log.read_text().splitlines()]
    assert len(rows) == 3 and {r[0] for r in rows} == {"add"}
    assert {r[1] for r in rows} == {record_name("example.org", identity), apex_name("example.org")}
    assert any(r[2].startswith("nt1;") for r in rows) and any(r[2] == plain_record(identity, ["https://node.example.org", "mailto:chains@node.example.org"]) for r in rows)
    assert "SAVED_FAKE_Token='secret-token'" in (home / "account.conf").read_text()         # acme.sh's own credential handling ran

    info = runner.invoke(cli, ["dns", "plugins", "--acme-home", str(home), "dns_fake"])
    assert info.exit_code == 0 and "Fake provider" in info.output and "FAKE_Token" in info.output
