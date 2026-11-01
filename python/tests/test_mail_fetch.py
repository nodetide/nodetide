"""mailto: distribution points: strict parsing, the node asking by email as a last resort, and the CLI."""

import json
from email import message_from_bytes, policy
from email.message import EmailMessage

import pytest
from click.testing import CliRunner

from nodetide.core.identity import Identity, Sigchain
from nodetide.core.storage import Storage
from nodetide.mailresponder.addresses import mail_points, mailto_address
from nodetide.mailresponder.fetch import MailFetchService, reply_dispatcher
from nodetide.mailresponder.responder import Responder, ResponderConfig
from nodetide.oidc.fetcher import IdentityFetcher
from nodetide.verifiers.mail import MemorySender

REMOTE = "chains@remote.example"
OURS = "chains@ours.example"


@pytest.mark.parametrize("point,expected", [
    ("mailto:chains@node.example", "chains@node.example"),
    ("MAILTO:Chains@Node.Example", "chains@node.example"),
    ("mailto:a.b+tag@sub.node.example", "a.b+tag@sub.node.example"),
])
def test_plain_addresses_are_accepted(point, expected):
    assert mailto_address(point) == expected


@pytest.mark.parametrize("point", [
    "mailto:chains@node.example?cc=victim@x.example", "mailto:a@x.example,b@y.example", "mailto:Chains <c@x.example>",
    "mailto:c%40x.example", "mailto:c@x", "mailto:@x.example", "mailto:c@x.example\r\nBcc: v@y.example", "mailto:",
    "https://node.example", "mailto:c@localhost", "mailto:c@x.example;y@z.example", "mailto:" + "a" * 70 + "@x.example",
    "mailto:c@exämple.org", None, 5, ["mailto:c@x.example"],
])
def test_anything_doubtful_is_refused(point):
    assert mailto_address(point) is None


def test_mail_points_keeps_order_and_drops_repeats_and_other_schemes():
    assert mail_points(["https://a.example", "mailto:b@x.example", "mailto:B@x.example", "mailto:c@x.example?x=1", "mailto:d@x.example"]) \
        == ["b@x.example", "d@x.example"]
    assert mail_points("mailto:a@x.example") == []


def behind_identity():
    """An identity that names a mail address; `old` is what our node holds, `ident` is ahead of it."""
    ident = Identity.create(name="Alice", distribution_points=["https://dead.example", f"mailto:{REMOTE}"])
    old = Sigchain.from_list(ident.sigchain.to_list())
    ident.add_device("phone")
    ident.add_device("laptop")
    return ident, old


class Setup:
    """Our node (storage, fetcher, mail service) and a remote node that holds the newer chain and answers mail."""

    def __init__(self, ident, stored):
        self.ident = ident
        self.storage = Storage.memory()
        self.storage.save_sigchain(stored)
        self.updates = []

        async def on_update(h):
            self.updates.append(h)

        async def no_http(base, h):
            return None

        self.fetcher = IdentityFetcher(self.storage, fetch=no_http, on_update=on_update)
        self.outbox = MemorySender()
        self.service = MailFetchService(self.outbox, OURS, deliver=self.fetcher.deliver)
        self.fetcher.mail = self.service
        remote_storage = Storage.memory()
        remote_storage.save_sigchain(ident.sigchain)
        self.remote_out = MemorySender()
        self.remote = Responder(remote_storage, self.remote_out, ResponderConfig(address=REMOTE, require_auth=False))
        self.ours = Responder(self.storage, MemorySender(), ResponderConfig(address=OURS, require_auth=False))
        self.dispatch = reply_dispatcher(self.ours, self.service)

    async def remote_answers(self) -> list[bytes]:
        """The remote node reads our requests and answers; what it sends back, as raw mail."""
        for request in self.outbox.messages:
            await self.remote.handle(request.as_bytes())
        self.outbox.messages.clear()
        replies = [m.as_bytes() for m in self.remote_out.messages]
        self.remote_out.messages.clear()
        return replies


async def test_the_fetcher_asks_by_email_and_takes_the_answer_when_it_arrives():
    ident, old = behind_identity()
    s = Setup(ident, old)
    s.fetcher.schedule(ident.identity_hash, want_head=ident.sigchain.head_hash)
    await s.fetcher.run_once()
    # http found nothing; one request went out, to the address in the identity's own distribution points
    assert len(s.outbox.messages) == 1 and s.outbox.messages[0]["To"] == REMOTE and s.outbox.messages[0]["From"] == OURS
    assert f"since={old.head_hash}" in s.outbox.messages[0].get_content()
    status = s.fetcher.status(ident.identity_hash)
    assert status["state"] == "pending" and status["last_error"] == "mailto: sent"

    for raw in await s.remote_answers():
        await s.dispatch(raw)
    stored = s.storage.get_sigchain(ident.identity_hash)
    assert stored.head_hash == ident.sigchain.head_hash and stored.verify() == (True, None)
    assert s.fetcher.status(ident.identity_hash)["state"] == "done"
    assert s.updates == [ident.identity_hash]


async def test_it_does_not_ask_twice_and_is_rationed():
    ident, old = behind_identity()
    s = Setup(ident, old)
    s.fetcher.schedule(ident.identity_hash, want_head=ident.sigchain.head_hash)
    await s.fetcher.run_once()
    assert len(s.outbox.messages) == 1
    # a retry while the answer is awaited sends nothing; another identity at the same address is held back for an hour
    assert await s.service.request(REMOTE, ident.identity_hash, old) == "waiting"
    other = Identity.create(name="Bob")
    assert await s.service.request(REMOTE, other.identity_hash) == "limited"
    assert await s.service.request(OURS, other.identity_hash) == "limited"          # never ourselves
    assert len(s.outbox.messages) == 1


async def test_hints_from_a_sign_in_never_cause_mail():
    ident, old = behind_identity()
    s = Setup(ident, old)
    plain = Identity.create(name="NoMail")          # stored, but names no mailbox
    s.storage.save_sigchain(plain.sigchain)
    s.fetcher.schedule(plain.identity_hash, hints=[f"mailto:{REMOTE}", "mailto:victim@elsewhere.example"], want_head="ab" * 32)
    await s.fetcher.run_once()
    assert s.outbox.messages == []


async def test_a_dead_mail_server_does_not_break_the_fetch_loop():
    ident, old = behind_identity()
    s = Setup(ident, old)
    s.outbox.fail = True
    s.fetcher.schedule(ident.identity_hash, want_head=ident.sigchain.head_hash)
    assert await s.fetcher.run_once() == 1
    status = s.fetcher.status(ident.identity_hash)
    assert status["attempts"] == 1 and "failed" in status["last_error"]


async def test_wrong_sender_and_tampered_answers_change_nothing():
    ident, old = behind_identity()
    s = Setup(ident, old)
    s.fetcher.schedule(ident.identity_hash, want_head=ident.sigchain.head_hash)
    await s.fetcher.run_once()
    (reply,) = await s.remote_answers()

    # from somebody else: not taken as the answer (it falls through to the responder, which has nothing to do with it)
    forged = message_from_bytes(reply, policy=policy.default)
    forged.replace_header("From", "attacker@evil.example")
    await s.dispatch(forged.as_bytes())
    assert s.storage.get_sigchain(ident.identity_hash).head_hash == old.head_hash

    # right sender, tampered chain: refused by the signatures, nothing stored
    tampered = message_from_bytes(reply, policy=policy.default)
    part = next(p for p in tampered.walk() if p.get_content_subtype() == "vnd.nodetide+json")
    data = json.loads(part.get_payload(decode=True))
    data["events"][0]["signature"] = "00" * 64
    part.set_content(json.dumps(data).encode(), maintype="application", subtype="vnd.nodetide+json", filename="nodetide.json")
    await s.dispatch(tampered.as_bytes())
    assert s.storage.get_sigchain(ident.identity_hash).head_hash == old.head_hash and s.service.pending == {}


async def test_ordinary_requests_still_reach_the_responder():
    ident, old = behind_identity()
    s = Setup(ident, old)
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Message-ID"] = "bob@gmail.com", OURS, "GET info", "<q1@gmail.com>"
    m.set_content("GET info\n")
    s.service.pending["<something@else>"] = object()          # a pending request makes the dispatcher look at replies first
    assert await s.dispatch(m.as_bytes()) == 1


# --- CLI ------------------------------------------------------------------------------------------------------------------

def test_cli_refuses_a_doubtful_mailto_and_uses_a_known_one(tmp_path, monkeypatch):
    from nodetide.cli.main import cli
    monkeypatch.setenv("NODETIDE_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(cli, ["identity", "create", "-n", "Alice"]).exit_code == 0
    bad = runner.invoke(cli, ["identity", "set-distribution", "-d", "mailto:a@x.example?cc=v@y.example"])
    assert bad.exit_code != 0 and "plain address" in bad.output
    ok = runner.invoke(cli, ["identity", "set-distribution", "-d", "https://relay.example", "-d", f"mailto:{REMOTE}"])
    assert ok.exit_code == 0 and f"mailto:{REMOTE}" in ok.output

    storage = Storage.open(tmp_path / "nodetide.db")
    mine = storage.get_default_identity().identity_hash
    other = Identity.create(name="NoPoints")
    storage.save_sigchain(other.sigchain)
    storage.close()
    env = {"NODETIDE_MAIL_FROM": "me@ours.example"}
    unknown = runner.invoke(cli, ["mail", "fetch", other.identity_hash], env=env)
    assert unknown.exit_code != 0 and "no mailto:" in unknown.output
    junk = runner.invoke(cli, ["mail", "fetch", mine, "--to", "x@y"], env=env)
    assert junk.exit_code != 0 and "not a plain mailbox" in junk.output
    # with a known point it gets as far as needing mail settings
    configured = runner.invoke(cli, ["mail", "fetch", mine], env=env)
    assert f"Asking {REMOTE}" in configured.output and configured.exit_code != 0 and "_HOST is not set" in configured.output
