"""A signed snapshot of an identity's current state, short enough for DNS, and checking assertions against it."""

import base64
import json
import time
import zlib

import pytest
from aiohttp.test_utils import TestClient, TestServer
from click.testing import CliRunner

from nodetide.api import create_app
from nodetide.core.auth import AuthRequest, create_assertion, verify_assertion_with_state
from nodetide.core.crypto import KeyPair
from nodetide.core.dns_source import DnsStateSource, dns_domains, dns_point, record_name
from nodetide.core.identity import DeviceCapability, Identity, Sigchain
from nodetide.core.state import (
    MAX_DEVICES, MAX_TEXT, PREFIX, StateError, build_state, decode, encode, txt_strings, verify_state,
)
from nodetide.core.storage import Storage

AUD = "https://app.example.com"
NODE_AUD = "https://node.test"


def make(devices=1, points=None):
    ident = Identity.create(name="Alice", distribution_points=points)
    keys = [ident.add_device(f"d{i}", capabilities=[DeviceCapability.AUTHENTICATE])[0] for i in range(devices)]
    return ident, keys


def state_of(ident, **kw):
    return build_state(ident.sigchain, ident.local_keypair, **kw)


def assertion_for(ident, device, head=None, aud=AUD):
    request = AuthRequest.new(aud=aud)
    return request, create_assertion(request, ident.identity_hash, device, head or ident.sigchain.head_hash)


# --- the document -----------------------------------------------------------------------------------------------------

def test_a_state_is_short_and_round_trips():
    ident, _ = make(devices=3)
    text = encode(state_of(ident))
    print("3 devices:", len(text), "characters")
    assert text.startswith(PREFIX) and len(text) < 2000
    assert all(len(p) <= 255 for p in txt_strings(text)) and "".join(txt_strings(text)) == text
    v = verify_state(decode(text), expect_identity=ident.identity_hash)
    assert v.identity_hash == ident.identity_hash and v.head_hash == ident.sigchain.head_hash
    assert v.master == ident.local_keypair.verify_key.to_hex() and len(v.devices) == 3
    assert v.length == len(ident.sigchain.events) and v.lineage_length == 1


def test_the_state_stays_short_however_long_the_chain_gets():
    ident, _ = make(devices=2)
    short = len(encode(state_of(ident)))
    for i in range(60):                                   # a long history: claims and devices coming and going
        ident.add_claim(f"{i:022d}", "email", f"{i:064x}")
    for i in range(10):
        key, _ = ident.add_device(f"tmp{i}")
        ident.revoke_device(key.verify_key.to_hex())
    assert len(ident.sigchain.events) > 15 and len(ident.sigchain.content) == 60
    long = len(encode(state_of(ident)))
    assert long - short < 200                              # commitment and counters only


def test_too_many_devices_or_rotations_are_refused_not_truncated():
    ident, _ = make(devices=MAX_DEVICES + 1)
    with pytest.raises(StateError, match="devices"):
        state_of(ident)


def test_only_the_current_master_can_publish():
    ident, _ = make()
    with pytest.raises(StateError, match="current master"):
        build_state(ident.sigchain, KeyPair.generate())


@pytest.mark.parametrize("text", ["", "nt1;", "nt1;!!!notbase64!!!", PREFIX + "AAAA", "v=spf1 -all", "x" * 10, PREFIX + "A" * (MAX_TEXT + 1)])
def test_garbage_is_not_a_state(text):
    with pytest.raises(StateError):
        decode(text)


def test_a_decompression_bomb_is_refused():
    bomb = PREFIX + base64.urlsafe_b64encode(zlib.compress(b" " * 2_500_000, 9)).decode().rstrip("=")
    assert len(bomb) < MAX_TEXT
    with pytest.raises(StateError, match="too much"):
        decode(bomb)


# --- what makes it trustworthy ----------------------------------------------------------------------------------------

def tamper(doc, fn):
    copy = json.loads(json.dumps(doc))
    fn(copy)
    return copy


def test_any_change_to_the_signed_state_is_caught():
    ident, _ = make(devices=1)
    doc = state_of(ident)
    verify_state(doc)
    mallory = KeyPair.generate().verify_key.to_hex()
    for name, fn in {
        "device added": lambda d: d["body"]["devices"].append({"k": mallory, "e": mallory, "c": ["authenticate"], "a": 0, "x": None}),
        "head changed": lambda d: d["body"].update(head="00" * 32),
        "expiry extended": lambda d: d["body"].update(exp=d["body"]["exp"] + 10**7),
        "capability widened": lambda d: d["body"]["devices"][0].update(c=["authenticate", "sign"]),
        "signature zeroed": lambda d: d.update(sig="00" * 64),
    }.items():
        with pytest.raises(StateError):
            verify_state(tamper(doc, fn))
        assert name


def test_the_state_must_belong_to_the_identity_asked_for():
    a, _ = make()
    b, _ = make()
    with pytest.raises(StateError, match="another identity"):
        verify_state(state_of(a), expect_identity=b.identity_hash)
    # nor can someone else's genesis be swapped in under a signature they cannot make
    doc = state_of(a)
    doc["lineage"] = state_of(b)["lineage"]
    with pytest.raises(StateError):
        verify_state(doc)


def test_freshness_is_checked_by_the_caller_not_assumed():
    ident, _ = make()
    now = int(time.time())
    doc = state_of(ident, now=now, validity=3600)
    verify_state(doc, now=now + 3000)
    with pytest.raises(StateError, match="expired"):
        verify_state(doc, now=now + 3600 + 301)
    with pytest.raises(StateError, match="future"):
        verify_state(doc, now=now - 1000)
    with pytest.raises(StateError, match="older than"):
        verify_state(doc, now=now + 1000, max_age=500)


def test_a_rotated_master_is_followed_and_the_old_one_no_longer_vouches():
    ident, _ = make()
    old_doc = state_of(ident)
    ident.rotate_master()
    new_doc = state_of(ident)
    v = verify_state(new_doc)
    assert v.lineage_length == 2 and v.master == ident.local_keypair.verify_key.to_hex()
    # an old snapshot still verifies as what it was (the old master did sign it) but names the old master
    assert verify_state(old_doc).master != v.master
    # a state signed by the new master that omits the rotation cannot be made to verify
    broken = tamper(new_doc, lambda d: d.update(lineage=d["lineage"][:1]))
    with pytest.raises(StateError, match="lineage does not lead"):
        verify_state(broken)
    # and a rotation not signed by the key before it is no rotation
    forged = tamper(new_doc, lambda d: d["lineage"][1].update(signature="00" * 64))
    with pytest.raises(StateError, match="rotation signature"):
        verify_state(forged)


# --- assertions against a state ---------------------------------------------------------------------------------------

def test_an_assertion_is_checked_against_the_state():
    ident, (device,) = make()
    v = verify_state(state_of(ident))
    _, a = assertion_for(ident, device)
    result = verify_assertion_with_state(a, v, AUD)
    assert result.ok and result.device == device.verify_key.to_hex()

    # a different head than the state's: the signer knows something we do not, or the state is old
    ident.add_device("later")
    _, ahead = assertion_for(ident, device)
    assert verify_assertion_with_state(ahead, v, AUD).code == "unknown_chain_head"
    # the master key may not sign assertions; an unknown device may not either
    _, by_master = assertion_for(ident, ident.local_keypair, head=v.head_hash)
    assert verify_assertion_with_state(by_master, v, AUD).code == "device_not_authorized"
    _, stranger = assertion_for(ident, KeyPair.generate(), head=v.head_hash)
    assert verify_assertion_with_state(stranger, v, AUD).code == "device_not_authorized"
    _, wrong_aud = assertion_for(ident, device, head=v.head_hash, aud="https://evil.example")
    assert verify_assertion_with_state(wrong_aud, v, AUD).code == "wrong_audience"


def test_a_revoked_device_is_not_in_a_state_made_after_the_revocation():
    ident, (device,) = make()
    ident.revoke_device(device.verify_key.to_hex())
    v = verify_state(state_of(ident))
    _, a = assertion_for(ident, device)
    assert verify_assertion_with_state(a, v, AUD).code == "device_not_authorized"


# --- DNS ------------------------------------------------------------------------------------------------------------------

def test_dns_points_are_plain_public_names():
    assert dns_point("dns:Example.ORG") == "example.org" and dns_point("dns:sub.example.org.") == "sub.example.org"
    for bad in ["dns:", "dns:localhost", "dns:example", "dns:192.168.1.5", "dns:8.8.8.8", "dns:nas.local", "dns:a b.example.org",
                "dns:-x.example.org", "dns:exa_mple.org", "dns:" + "a" * 64 + ".org", "dns:例え.jp", "https://example.org", None, 5,
                "dns:example.org/path", "dns:x.example.org:53", "dns:host.internal", "dns:foo.test"]:
        assert dns_point(bad) is None, bad
    assert dns_domains(["https://a.example", "dns:b.example.org", "dns:B.example.org", "dns:bad"]) == ["b.example.org"]


def test_the_record_name_fits_a_dns_label():
    ident, _ = make()
    name = record_name("example.org", ident.identity_hash)
    assert name == f"{ident.identity_hash[:32]}._nodetide.example.org" and all(len(label) <= 63 for label in name.split("."))


class FakeDns:
    def __init__(self, records):
        self.records, self.calls = records, 0

    async def __call__(self, name):
        self.calls += 1
        return self.records.get(name, [])


async def test_the_source_returns_a_verified_state_and_ignores_the_rest():
    ident, _ = make()
    name = record_name("example.org", ident.identity_hash)
    other, _ = make()
    dns = FakeDns({name: ["v=spf1 -all", "nt1;garbage", encode(state_of(other)), encode(state_of(ident))]})
    source = DnsStateSource(lookup=dns)
    state = await source.fetch("example.org", ident.identity_hash)
    assert state is not None and state.identity_hash == ident.identity_hash
    await source.fetch("example.org", ident.identity_hash)
    assert dns.calls == 1                                                      # cached
    assert await DnsStateSource(lookup=FakeDns({})).fetch("example.org", ident.identity_hash) is None
    assert await source.fetch("localhost", ident.identity_hash) is None and await source.fetch("example.org", "zz") is None


async def test_the_source_takes_the_newest_valid_record_and_survives_a_failing_resolver():
    ident, _ = make()
    now = int(time.time())
    old, new = encode(state_of(ident, now=now - 100)), encode(state_of(ident, now=now - 10))
    name = record_name("example.org", ident.identity_hash)
    assert (await DnsStateSource(lookup=FakeDns({name: [old, new]})).fetch("example.org", ident.identity_hash)).timestamp == now - 10

    async def broken(name):
        raise OSError("resolver down")
    assert await DnsStateSource(lookup=broken).fetch("example.org", ident.identity_hash) is None


# --- the node -------------------------------------------------------------------------------------------------------------

@pytest.fixture
async def node():
    storage = Storage.memory()
    app = create_app(storage=storage, auth_audience=NODE_AUD)
    dns = FakeDns({})
    app["dns_state"] = DnsStateSource(lookup=dns)
    async with TestClient(TestServer(app)) as c:
        c.storage, c.dns = storage, dns
        yield c


async def challenge(client, aud=AUD):
    resp = await client.post("/api/auth/challenge", json={"aud": aud})
    assert resp.status == 201
    return await resp.json()


async def test_the_node_accepts_a_supplied_state_for_an_identity_it_never_saw(node):
    ident, (device,) = make()
    request = await challenge(node)
    a = create_assertion(request, ident.identity_hash, device, ident.sigchain.head_hash)
    body = {"assertion": a}
    assert (await node.post("/api/auth/verify", json=body)).status == 404                    # nothing known, nothing supplied
    resp = await node.post("/api/auth/verify", json=body | {"state": state_of(ident)})
    assert resp.status == 200, await resp.text()


async def test_a_bad_supplied_state_does_not_authenticate(node):
    ident, (device,) = make()
    request = await challenge(node)
    a = create_assertion(request, ident.identity_hash, device, ident.sigchain.head_hash)
    doc = tamper(state_of(ident), lambda d: d["body"].update(head="00" * 32))
    resp = await node.post("/api/auth/verify", json={"assertion": a, "state": doc})
    assert resp.status == 404                                                                # as if no state: the state is simply ignored
    other, _ = make()
    resp = await node.post("/api/auth/verify", json={"assertion": a, "state": state_of(other)})
    assert resp.status == 404


async def test_a_stale_stored_chain_is_rescued_by_the_state_in_dns_named_in_that_chain(node):
    ident, (device,) = make(points=["https://dead.example", "dns:example.org"])
    node.storage.save_sigchain(Sigchain(events=list(ident.sigchain.events)))
    ident.add_device("laptop")                                                              # the signer is ahead of the node
    request = await challenge(node)
    a = create_assertion(request, ident.identity_hash, device, ident.sigchain.head_hash)
    assert (await node.post("/api/auth/verify", json={"assertion": a})).status == 409       # nothing in DNS yet

    node.dns.records[record_name("example.org", ident.identity_hash)] = [encode(state_of(ident))]
    node.app["dns_state"]._cache.clear()
    request = await challenge(node)
    a = create_assertion(request, ident.identity_hash, device, ident.sigchain.head_hash)
    resp = await node.post("/api/auth/verify", json={"assertion": a})
    assert resp.status == 200, await resp.text()
    # the stored chain was not touched: a state authenticates, it does not rewrite history
    assert node.storage.get_sigchain(ident.identity_hash).head_hash != ident.sigchain.head_hash


async def test_the_caller_may_name_the_domain_for_an_unknown_identity(node):
    ident, (device,) = make()
    node.dns.records[record_name("example.org", ident.identity_hash)] = [encode(state_of(ident))]
    request = await challenge(node)
    a = create_assertion(request, ident.identity_hash, device, ident.sigchain.head_hash)
    assert (await node.post("/api/auth/verify", json={"assertion": a, "dns": "evil..example"})).status == 404
    resp = await node.post("/api/auth/verify", json={"assertion": a, "dns": "example.org"})
    assert resp.status == 200


# --- CLI ------------------------------------------------------------------------------------------------------------------

def test_cli_prints_the_record_and_checks_the_distribution_point(tmp_path, monkeypatch):
    from nodetide.cli.main import cli
    monkeypatch.setenv("NODETIDE_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(cli, ["identity", "create", "-n", "Alice"]).exit_code == 0
    assert runner.invoke(cli, ["identity", "dns-record"]).exit_code != 0                     # no dns: point yet
    bad = runner.invoke(cli, ["identity", "set-distribution", "-d", "dns:192.168.1.5"])
    assert bad.exit_code != 0 and "public domain" in bad.output
    assert runner.invoke(cli, ["identity", "set-distribution", "-d", "dns:example.org"]).exit_code == 0
    out = runner.invoke(cli, ["identity", "dns-record", "--json"])
    assert out.exit_code == 0, out.output
    record = json.loads(out.output)
    assert record["type"] == "TXT" and record["name"].endswith("._nodetide.example.org")
    state = verify_state(decode("".join(record["strings"])))
    assert state.identity_hash == record["name"].split(".")[0] + state.identity_hash[32:]
