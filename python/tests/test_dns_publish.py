"""Publishing DNS records: nsupdate scripts, acme.sh plugins, and never touching what is not ours."""

import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nodetide.core.dns_source import apex_name, plain_record, record_name
from nodetide.core.identity import Identity
from nodetide.core.state import PREFIX
from nodetide.core.storage import Storage
from nodetide.dnspublish.acme import AcmeError, AcmePublisher, check_plugin
from nodetide.dnspublish.nsupdate import Key, NsupdateError, NsupdatePublisher, fqdn, script, txt_rdata
from nodetide.dnspublish.publish import plan_publish, plan_remove
from nodetide.dnspublish.records import Desired, build_desired

DOMAIN = "example.org"


def ident(points=("dns:example.org", "https://node.example.org")):
    i = Identity.create(name="Alice", distribution_points=list(points))
    i.add_device("phone")
    return i


# --- nsupdate script ------------------------------------------------------------------------------------------------

def test_txt_rdata_splits_at_255_and_escapes():
    long = "a" * 600
    parts = txt_rdata(long).split(" ")
    assert [len(p) - 2 for p in parts] == [255, 255, 90] and all(p.startswith('"') and p.endswith('"') for p in parts)
    assert txt_rdata('say "hi" \\ there') == '"say \\"hi\\" \\\\ there"'
    assert txt_rdata("") == '""'
    for bad in ["é", "tab\there", "nl\n", "del\x7f"]:
        with pytest.raises(NsupdateError):
            txt_rdata(bad)


def test_the_script_is_one_transaction_with_absolute_names():
    text = script("ns1.example.org", "example.org", 300, [("x._nodetide.example.org", "old")], [("x._nodetide.example.org", "new"), ("_nodetide.example.org", "p")])
    assert text.splitlines() == [
        "server ns1.example.org", "zone example.org.",
        'update delete x._nodetide.example.org. TXT "old"',
        'update add x._nodetide.example.org. 300 TXT "new"', 'update add _nodetide.example.org. 300 TXT "p"', "send",
    ]
    assert fqdn("a.b.") == "a.b." and script(None, None, 60, [], []).splitlines() == ["send"]


def test_keys():
    k = Key.parse("hmac-sha512:mykey:c2VjcmV0")
    assert (k.algorithm, k.name, k.secret) == ("hmac-sha512", "mykey", "c2VjcmV0")
    assert Key.parse("mykey:c2VjcmV0").algorithm == "hmac-sha256"
    for bad in ["", "onlyname", "a:b:c:d", "md5x:name:secret", "name:sec ret", 'na"me:secret', "name:"]:
        with pytest.raises(NsupdateError):
            Key.parse(bad)


class FakeRun:
    def __init__(self, returncode=0, stderr=""):
        self.calls, self.rc, self.err = [], returncode, stderr

    def __call__(self, cmd, **kw):
        keyfile = cmd[cmd.index("-k") + 1] if "-k" in cmd else None
        self.calls.append({"cmd": cmd, "input": kw.get("input"), "env": kw.get("env"), "key_text": Path(keyfile).read_text() if keyfile and os.path.exists(keyfile) else None, "keyfile": keyfile})
        return subprocess.CompletedProcess(cmd, self.rc, stdout="", stderr=self.err)


def test_a_secret_key_goes_through_a_private_temporary_file_never_the_command_line():
    run = FakeRun()
    pub = NsupdatePublisher(server="127.0.0.1", port=5300, zone="example.org", key=Key.parse("k1:c2VjcmV0"), executable="/usr/bin/nsupdate", runner=run)
    pub.apply([("a.example.org", "old")], [("a.example.org", "new")], 300)
    (call,) = run.calls
    assert "c2VjcmV0" not in " ".join(call["cmd"]) and call["cmd"][:2] == ["/usr/bin/nsupdate", "-v"] and "5300" in call["cmd"]
    assert 'key "k1"' in call["key_text"] and 'secret "c2VjcmV0"' in call["key_text"] and not os.path.exists(call["keyfile"])      # gone afterwards
    assert call["input"].splitlines()[:2] == ["server 127.0.0.1", "zone example.org."]


def test_nsupdate_failures_are_reported_and_a_missing_tool_is_explained(tmp_path):
    keyfile = tmp_path / "k"
    keyfile.write_text("x")
    with pytest.raises(NsupdateError, match="REFUSED"):
        NsupdatePublisher(server="s", key=Key(file=str(keyfile)), executable="/x", runner=FakeRun(1, "update failed: REFUSED")).apply([], [("a", "b")], 60)
    pub = NsupdatePublisher(server="s", executable=None)
    pub.executable = None
    with pytest.raises(NsupdateError, match="not installed"):
        pub.apply([], [("a", "b")], 60)


# --- what is ours ---------------------------------------------------------------------------------------------------

async def test_only_our_values_are_replaced_and_foreign_ones_are_left_alone():
    i = ident()
    desired = build_desired(i.sigchain, i.local_keypair, DOMAIN, 7 * 86400)
    own, apex = record_name(DOMAIN, i.identity_hash), apex_name(DOMAIN)
    state, plain = desired.records[own]
    other_plain = plain_record("cd" * 32, ["https://other.example.org"])
    old_state = PREFIX + "oldstate"
    old_plain = plain_record(i.identity_hash, ["https://old.example.org"])
    zone = {own: [old_state, old_plain, "v=spf1 -all"], apex: [other_plain, old_plain]}

    async def lookup(n):
        return zone.get(n, [])

    plan = await plan_publish(desired, lookup)
    assert sorted(plan.removes) == sorted([(own, old_state), (own, old_plain), (apex, old_plain)])
    assert sorted(plan.adds) == sorted([(own, state), (own, plain), (apex, plain)])
    # the other identity's entry at the domain's name, and an SPF value at our name, are never in the plan
    assert (apex, other_plain) in plan.foreign and (own, "v=spf1 -all") in plan.foreign and not any(v in (other_plain, "v=spf1 -all") for _, v in plan.removes)

    # up to date: nothing to do; and taking everything down removes only ours
    zone[own], zone[apex] = [state, plain, "v=spf1 -all"], [other_plain, plain]
    assert (await plan_publish(desired, lookup)).empty
    gone = await plan_remove(desired, lookup)
    assert sorted(gone.removes) == sorted([(own, state), (own, plain), (apex, plain)]) and (apex, other_plain) in gone.foreign


def test_without_the_apex_entry_only_the_identitys_own_name_is_involved():
    i = ident()
    desired = build_desired(i.sigchain, i.local_keypair, DOMAIN, 3600, apex=False)
    assert list(desired.records) == [record_name(DOMAIN, i.identity_hash)]


# --- acme.sh plugins ------------------------------------------------------------------------------------------------

def make_home(tmp_path, plugin="dns_fake"):
    home = tmp_path / "acme"
    (home / "dnsapi").mkdir(parents=True)
    (home / "acme.sh").write_text("#!/bin/sh\n")
    (home / "dnsapi" / f"{plugin}.sh").write_text("#\n")
    return home


def test_plugin_names_and_homes_are_checked(tmp_path):
    assert check_plugin("cf") == "dns_cf" and check_plugin("dns_cf") == "dns_cf"
    for bad in ["../x", "dns_x; rm", "dns_", "DNS_CF", "dns_a b", "dns_" + "a" * 50]:
        with pytest.raises(AcmeError):
            check_plugin(bad)
    with pytest.raises(AcmeError, match="no acme.sh"):
        AcmePublisher("dns_fake", tmp_path / "nowhere")
    with pytest.raises(AcmeError, match="does not exist"):
        AcmePublisher("dns_missing", make_home(tmp_path))


def test_acme_adds_before_it_removes_and_keeps_the_value_off_the_command_line(tmp_path):
    calls = []

    def run(cmd, env=None, **kw):
        calls.append((cmd, env["NT_VALUE"], env.get("CF_Token")))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    pub = AcmePublisher("dns_fake", make_home(tmp_path), env={"CF_Token": "tok", "PATH": os.environ["PATH"]}, runner=run)
    pub.apply([("n1.example.org.", "OLD")], [("n1.example.org", "NEW; with spaces"), ("n2.example.org", "P")], 300)
    assert [(c[0][-2], c[0][-1], c[1]) for c in calls] == [("add", "n1.example.org", "NEW; with spaces"), ("add", "n2.example.org", "P"), ("rm", "n1.example.org", "OLD")]
    assert all("NEW" not in " ".join(c[0]) and c[2] == "tok" for c in calls)                 # credentials reach the plugin through the environment


def test_a_failing_plugin_says_why(tmp_path):
    def run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, stdout="[ts] no FAKE_Token\n", stderr="")
    with pytest.raises(AcmeError, match="no FAKE_Token"):
        AcmePublisher("dns_fake", make_home(tmp_path), runner=run).apply([], [("a.example.org", "v")], 300)


# --- the CLI ------------------------------------------------------------------------------------------------------

@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    from nodetide.cli.main import cli
    monkeypatch.setenv("NODETIDE_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(cli, ["identity", "create", "-n", "Alice"]).exit_code == 0
    assert runner.invoke(cli, ["identity", "set-distribution", "-d", "dns:example.org", "-d", "https://node.example.org"]).exit_code == 0
    storage = Storage.open(tmp_path / "nodetide.db")
    me = storage.get_default_identity().identity_hash
    storage.close()
    return cli, runner, me, tmp_path


def test_dns_record_in_zone_and_nsupdate_formats(cli_env):
    cli, runner, me, _ = cli_env
    zone = runner.invoke(cli, ["identity", "dns-record", "--format", "zone", "--ttl", "120"]).output.splitlines()
    assert len(zone) == 3 and all(" 120 IN TXT " in l for l in zone) and zone[0].startswith(f"{me[:32]}._nodetide.example.org. ")
    assert zone[2].startswith("_nodetide.example.org. ")
    script_text = runner.invoke(cli, ["identity", "dns-record", "--format", "nsupdate", "--no-apex"]).output.splitlines()
    assert script_text[0] == "zone example.org." and script_text[-1] == "send" and len([l for l in script_text if l.startswith("update add")]) == 2
    assert script_text[1] == f"update delete {me[:32]}._nodetide.example.org. TXT"          # the identity's own name is ours alone: replaced, not piled up


def test_dns_publish_dry_run_and_errors(cli_env, monkeypatch):
    cli, runner, me, _ = cli_env
    asked = []

    async def fake_lookup(name):
        asked.append(name)
        return []

    monkeypatch.setattr("nodetide.dnspublish.publish.authoritative_lookup", lambda server, port=53, timeout=5.0: fake_lookup)
    out = runner.invoke(cli, ["identity", "dns-publish", "--method", "nsupdate", "--nsupdate-server", "127.0.0.1", "--dry-run"])
    assert out.exit_code == 0, out.output
    assert out.output.count("  add ") == 3 and "dry run" in out.output and asked == [record_name(DOMAIN, me), apex_name(DOMAIN)]
    assert runner.invoke(cli, ["identity", "dns-publish", "--method", "nsupdate"]).exit_code != 0                 # no server
    assert runner.invoke(cli, ["identity", "dns-publish", "--method", "acme"]).exit_code != 0                      # no plugin
    bad = runner.invoke(cli, ["identity", "dns-publish", "--method", "acme", "--acme-plugin", "dns_x", "--acme-home", "/nonexistent"])
    assert bad.exit_code != 0 and "no acme.sh" in bad.output
    assert runner.invoke(cli, ["identity", "dns-publish", "-d", "192.168.1.5", "--method", "nsupdate", "--nsupdate-server", "x"]).exit_code != 0


def test_plugins_are_listed_from_an_acme_home(cli_env, tmp_path):
    cli, runner, _, _ = cli_env
    home = make_home(tmp_path)
    (home / "dnsapi" / "dns_other.sh").write_text("#\n")
    (home / "dnsapi" / "notes.txt").write_text("x")
    out = runner.invoke(cli, ["dns", "plugins", "--acme-home", str(home)])
    assert out.output.split() == ["dns_fake", "dns_other"]
    assert runner.invoke(cli, ["dns", "plugins", "--acme-home", str(tmp_path / "none")]).exit_code != 0
