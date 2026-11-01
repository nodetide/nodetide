"""Sigchain distribution by email: grammar, abuse limits, reply format, and a client/responder loop."""

import json
from email.message import EmailMessage

import pytest

from nodetide.core.identity import Identity
from nodetide.core.claims import ClaimDocument
from nodetide.core.storage import Storage
from nodetide.mailresponder.client import (
    MailClient, MailFetchError, build_request, chain_from_reply, join_parts, payloads,
)
from nodetide.mailresponder.limits import authenticated, is_automatic, sender_address
from nodetide.mailresponder.protocol import Command, parse_commands, parse_line
from nodetide.mailresponder.responder import Responder, ResponderConfig
from nodetide.verifiers.mail import MemorySender

H = "ab" * 32
NODE = "chains@node.example"


def identity(claims=0, devices=0):
    ident = Identity.create(name="Alice")
    for i in range(claims):
        doc = ClaimDocument.create(ident.identity_hash, "email", f"a{i}@example.com")
        ident.add_claim(doc.claim_id, doc.claim_type, doc.commitment)
    for i in range(devices):
        ident.add_device(f"d{i}")
    return ident


@pytest.fixture
def storage(tmp_path):
    return Storage.open(tmp_path / "n.db")


def mail(body, sender="bob@example.org", subject="hi", auth=True, headers=None, mid="<m1@example.org>"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Message-ID"] = sender, NODE, subject, mid
    if auth:
        m["Authentication-Results"] = "mx.node.example; dmarc=pass header.from=example.org"
    for k, v in (headers or {}).items():
        m[k] = v
    m.set_content(body)
    return m.as_bytes()


def make(storage, **cfg):
    out = MemorySender()
    return Responder(storage, out, ResponderConfig(address=NODE, **cfg)), out


# --- grammar ---------------------------------------------------------------------------------------------------------

def test_commands_are_read_strictly():
    assert parse_line(f"GET chain {H}") == Command("chain", H)
    assert parse_line(f"get CHAIN {H.upper()} light since={'cd' * 32}") == Command("chain", H, light=True, since="cd" * 32)
    assert parse_line(f"GET chain {H} since={'cd' * 32} from=4") == Command("chain", H, since="cd" * 32, content_from=4)
    assert parse_line(f"GET content {H} 3") == Command("content", H, seq=3)
    assert parse_line("GET info") == Command("info")
    for bad in ["GET chain abc", f"GET chain {H} drop table", f"GET chain {H}; GET info", f"GET content {H} -1",
                f"GET content {H} 99999999999", "PUT chain", "", f"GET chain {H} since=zz"]:
        assert parse_line(bad) is None, bad


def test_only_real_lines_count_not_quotes_or_signatures():
    body = f"Hello!\n> GET chain {'cd' * 32}\nGET info\nGET info\nGET chain {H} light\n-- \nGET content {H} 1\n"
    assert parse_commands(body) == [Command("info"), Command("chain", H, light=True)]
    assert parse_commands("nothing here", subject=f"GET chain {H}") == [Command("chain", H)]
    assert parse_commands(f"GET info\n", subject=f"GET chain {H}") == [Command("info")]
    many = "".join(f"GET content {H} {i}\n" for i in range(50))
    assert len(parse_commands(many)) == 5


# --- who is answered -------------------------------------------------------------------------------------------------

def test_authentication_results_must_come_from_our_server_and_match_the_from_domain():
    def msg(results, sender="bob@example.org"):
        m = EmailMessage()
        m["From"] = sender
        for r in results:
            m["Authentication-Results"] = r
        return m
    assert authenticated(msg(["mx.node.example; dmarc=pass header.from=example.org"]))
    assert authenticated(msg(["mx.node.example; dkim=pass header.d=example.org"]))
    assert authenticated(msg(["mx.node.example; dkim=pass header.d=mail.example.org"]))
    assert authenticated(msg(["mx.node.example; spf=pass smtp.mailfrom=bounce@example.org"]))
    assert not authenticated(msg([]))
    assert not authenticated(msg(["mx.node.example; dmarc=fail header.from=example.org"]))
    assert not authenticated(msg(["mx.node.example; dkim=pass header.d=evil.test"]))            # a signature for another domain
    assert not authenticated(msg(["mx.node.example; dkim=pass header.d=org"]))                  # a bare TLD is no domain
    assert not authenticated(msg(["mx.node.example; spf=pass smtp.mailfrom=x@evil.test"]))
    # a header an outsider wrote (forged authserv-id) does not count when we know our server's name
    forged = msg(["attacker.test; dmarc=pass"])
    assert authenticated(forged) and not authenticated(forged, trusted_servers=["mx.node.example"])
    assert authenticated(msg(["MX.node.example; dmarc=pass"]), trusted_servers=["mx.node.example"])


def test_sender_is_the_single_from_address_never_reply_to():
    m = EmailMessage()
    m["From"], m["Reply-To"] = "Bob <Bob@Example.org>", "victim@elsewhere.test"
    assert sender_address(m) == "bob@example.org"
    from email import message_from_bytes
    two = message_from_bytes(b"From: a@example.org\nFrom: b@example.org\n\nx\n")
    assert sender_address(two) is None
    assert sender_address(EmailMessage()) is None


async def test_machines_and_strangers_get_no_reply(storage):
    r, out = make(storage)
    ident = identity()
    storage.save_sigchain(ident.sigchain)
    ask = f"GET chain {ident.identity_hash}\n"
    for kind, raw in {
        "automatic": mail(ask, headers={"Auto-Submitted": "auto-replied"}, mid="<a@x>"),
        "automatic ": mail(ask, headers={"Precedence": "bulk"}, mid="<b@x>"),
        "automatic  ": mail(ask, headers={"List-Id": "<l.example.org>"}, mid="<c@x>"),
        "automatic   ": mail(ask, sender="mailer-daemon@example.org", mid="<d@x>"),
        "automatic    ": mail(ask, sender=NODE, mid="<e@x>"),
        "unauthenticated": mail(ask, auth=False, mid="<f@x>"),
        "unparseable": b"",
    }.items():
        assert await r.handle(raw) == 0, kind
    assert out.messages == []
    assert r.stats.dropped["automatic"] == 5 and r.stats.dropped["unauthenticated"] == 1
    assert is_automatic(EmailMessage()) is False


async def test_a_retried_message_is_answered_once(storage):
    r, out = make(storage)
    raw = mail("GET info\n")
    assert await r.handle(raw) == 1
    assert await r.handle(raw) == 0
    assert r.stats.dropped["duplicate"] == 1 and len(out.messages) == 1


async def test_oversized_requests_are_dropped_unread(storage):
    r, out = make(storage, max_message_bytes=1000)
    assert await r.handle(mail("GET info\n" + "x" * 5000)) == 0 and r.stats.dropped["too_large"] == 1


async def test_rate_limits_per_sender_domain_and_total(storage):
    now = [0.0]
    out = MemorySender()
    r = Responder(storage, out, ResponderConfig(address=NODE, per_sender=(2, 60), per_domain=(3, 60)), clock=lambda: now[0])
    async def ask(n, sender="bob@example.org"):
        return await r.handle(mail("GET info\n", sender=sender, mid=f"<{sender}{n}@x>"))
    assert [await ask(i) for i in range(3)] == [1, 1, 0]                       # bob: 2 per window
    assert await ask(0, "carol@example.org") == 1                              # domain: 3rd request
    assert await ask(0, "dan@example.org") == 0                                # domain budget used
    assert await ask(0, "erin@other.test") == 1
    now[0] = 61
    assert await ask(9) == 1                                                   # the window slid
    assert r.stats.dropped["rate_limited"] == 2


async def test_a_sender_cannot_pull_unlimited_bytes(storage):
    ident = identity(devices=20)
    storage.save_sigchain(ident.sigchain)
    r, out = make(storage, part_bytes=3000, max_parts=50, bytes_per_sender=(10_000, 3600))
    await r.handle(mail(f"GET chain {ident.identity_hash}\n"))
    full = sum(len(m.as_bytes()) for m in out.messages)
    assert out.messages and full <= 10_000 and r.stats.dropped["byte_budget"] == 1   # cut off at the budget, not sent whole
    assert len(out.messages) < 10


# --- answers ---------------------------------------------------------------------------------------------------------

async def test_a_chain_request_is_answered_with_an_attachment_threaded_to_the_request(storage):
    ident = identity(claims=2, devices=1)
    storage.save_sigchain(ident.sigchain)
    r, out = make(storage)
    assert await r.handle(mail(f"Hi,\nGET chain {ident.identity_hash}\nThanks\n")) == 1
    reply = out.messages[0]
    assert reply["To"] == "bob@example.org" and reply["From"] == NODE
    assert reply["In-Reply-To"] == "<m1@example.org>" and reply["Auto-Submitted"] == "auto-replied"
    (answer,) = payloads(reply)
    assert answer["kind"] == "chain" and answer["head_hash"] == ident.sigchain.head_hash
    assert len(answer["events"]) == 1 + 1 + 2          # genesis, add_device, two claims
    chain = chain_from_reply(join_parts([answer]))
    assert chain.head_hash == ident.sigchain.head_hash and chain.verify() == (True, None)


async def test_light_chain_and_content_proof(storage):
    ident = identity(claims=3, devices=1)
    storage.save_sigchain(ident.sigchain)
    r, out = make(storage)
    await r.handle(mail(f"GET chain {ident.identity_hash} light\nGET content {ident.identity_hash} 1\nGET content {ident.identity_hash} 99\n"))
    light, content, missing = (payloads(m)[0] for m in out.messages)
    assert light["light"] is True and len(light["events"]) == 2 and light["content_length"] == 3
    assert content["kind"] == "content" and content["event"]["seq"] == 1 and content["proof"] and content["committed_by"]
    assert missing["kind"] == "not_found"
    chain = chain_from_reply(join_parts([light]))
    assert chain.is_partial


async def test_unknown_identity_and_no_command(storage):
    r, out = make(storage)
    await r.handle(mail(f"GET chain {H}\n", mid="<1@x>"))
    await r.handle(mail("just saying hello\n", mid="<2@x>"))
    assert payloads(out.messages[0])[0]["kind"] == "not_found"
    assert payloads(out.messages[1]) == [] and "GET chain" in out.messages[1].get_body().get_content()


async def test_since_sends_only_the_new_control_events(storage):
    ident = identity(devices=1)
    old = ident.sigchain.head_hash
    old_chain = type(ident.sigchain).from_list(ident.sigchain.to_list())
    ident.add_device("d2")
    ident.add_device("d3")
    storage.save_sigchain(ident.sigchain)
    r, out = make(storage)
    await r.handle(mail(f"GET chain {ident.identity_hash} since={old}\n"))
    (answer,) = payloads(out.messages[0])
    assert answer["since"] == old and len(answer["events"]) == 2
    chain = chain_from_reply(join_parts([answer]), have=old_chain)
    assert chain.head_hash == ident.sigchain.head_hash
    with pytest.raises(MailFetchError, match="do not hold"):
        chain_from_reply(join_parts([answer]), have=None)
    # an unknown `since` falls back to the whole chain
    out.messages.clear()
    await r.handle(mail(f"GET chain {ident.identity_hash} since={'cd' * 32}\n", mid="<2@x>"))
    assert payloads(out.messages[0])[0]["since"] is None and len(payloads(out.messages[0])[0]["events"]) == 4


async def test_big_answers_are_split_and_reassembled_or_refused(storage):
    ident = identity(devices=12)
    storage.save_sigchain(ident.sigchain)
    r, out = make(storage, part_bytes=2500, max_parts=50)
    await r.handle(mail(f"GET chain {ident.identity_hash}\n"))
    assert len(out.messages) > 2
    items = [payloads(m)[0] for m in out.messages]
    assert all(i["parts"] == len(items) for i in items)
    with pytest.raises(MailFetchError, match="incomplete"):
        join_parts(items[:-1])
    chain = chain_from_reply(join_parts(list(reversed(items))))             # order does not matter
    assert chain.head_hash == ident.sigchain.head_hash

    out.messages.clear()
    strict, out2 = make(storage, part_bytes=2500, max_parts=2)
    await strict.handle(mail(f"GET chain {ident.identity_hash}\n"))
    assert len(out2.messages) == 1 and payloads(out2.messages[0])[0]["kind"] == "too_large"


def test_a_reply_that_lies_does_not_pass(storage):
    ident = identity(devices=2)
    answer = {"kind": "chain", "identity_hash": ident.identity_hash, "head_hash": ident.sigchain.head_hash,
              "events": ident.sigchain.to_list(light=True), "since": None}
    assert chain_from_reply(answer).head_hash == ident.sigchain.head_hash
    tampered = json.loads(json.dumps(answer))
    tampered["events"][1]["label"] = "evil" if "label" in tampered["events"][1] else None
    tampered["events"][1]["signature"] = "00" * 64
    with pytest.raises(MailFetchError):
        chain_from_reply(tampered)
    other = identity()
    with pytest.raises(MailFetchError, match="not the identity"):
        chain_from_reply(answer | {"identity_hash": other.identity_hash})
    with pytest.raises(MailFetchError, match="does not end"):
        chain_from_reply(answer | {"head_hash": "ee" * 32})
    with pytest.raises(MailFetchError):
        chain_from_reply({"kind": "info"})


# --- the whole loop ---------------------------------------------------------------------------------------------------

class Loop:
    """A tiny mail system: the client's sends go to the responder, its replies land in the client's mailbox."""

    def __init__(self, responder, client_address):
        self.responder, self.client_address, self.inbox = responder, client_address, []

    async def send_message(self, message):                   # client -> node
        message["Authentication-Results"] = "mx.node.example; dmarc=pass header.from=" + self.client_address.rpartition("@")[2]
        await self.responder.handle(message.as_bytes())

    def fetch_unseen(self, search="UNSEEN", mark_seen=True):  # node -> client
        mid = search.split('"')[1]
        return [m.as_bytes() for m in self.responder.sender.messages if m["In-Reply-To"] == mid]


async def test_client_fetches_and_verifies_a_chain_through_the_responder(storage):
    ident = identity(claims=1, devices=2)
    storage.save_sigchain(ident.sigchain)
    r, out = make(storage, part_bytes=2000, max_parts=20)
    loop = Loop(r, "alice@example.com")
    client = MailClient(loop, loop, "alice@example.com", NODE)
    chain = await client.fetch_chain(ident.identity_hash, timeout=5, interval=0.01)
    assert chain.head_hash == ident.sigchain.head_hash and chain.verify() == (True, None)
    assert len(chain.content) == 1

    # next time only what is new
    newer = identity()
    with pytest.raises(MailFetchError, match="does not know"):
        await client.fetch_chain(newer.identity_hash, timeout=5, interval=0.01)
    ident.add_device("d3")
    storage.save_sigchain(ident.sigchain)
    out.messages.clear()
    again = await client.fetch_chain(ident.identity_hash, have=chain, timeout=5, interval=0.01)
    assert again.head_hash == ident.sigchain.head_hash
    sent = payloads(out.messages[0])[0]
    assert len(sent["events"]) == 1 and sent["content_from"] == 1       # one new control event; the claim it already holds is not resent
    assert len(again.content) == 1


def test_request_message_shape():
    m = build_request("a@example.com", NODE, [Command("chain", H, light=True), Command("info")])
    assert m["Subject"] == f"GET chain {H} light"
    assert m.get_content().splitlines() == [f"GET chain {H} light", "GET info"]
