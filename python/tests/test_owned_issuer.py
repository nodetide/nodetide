"""An attestation issuer that is an organization with owners: it runs itself with its own key; owners found it."""

import pytest

from nodetide.core.claims import ClaimDocument, verify_attestation, verify_revocation
from nodetide.core.crypto import KeyPair
from nodetide.core.identity import Identity, RotateMasterEvent, Sigchain, SigchainEvent, approve, propose_governed
from nodetide.core.storage import Storage
from nodetide.verifiers.issuer import IssuerNotReady, founding_request, load_owned, parse_owners


def found(request: dict, owner: Identity) -> Sigchain:
    genesis = SigchainEvent.from_dict(request["genesis"])
    approve(genesis, owner.identity_hash, owner.local_keypair, owner.sigchain.head_hash)
    return Sigchain(events=[genesis])


def test_parse_owners():
    assert parse_owners("ab, cd:30") == [{"identity": "ab", "weight": 100}, {"identity": "cd", "weight": 30}]
    with pytest.raises(IssuerNotReady, match="OWNERS"):
        parse_owners("")


def test_owned_issuer_lifecycle():
    db = Storage.memory()
    owner = Identity.create(name="me")
    owners = owner.identity_hash

    request = founding_request(db, "My verifier", owners)
    assert founding_request(db, "My verifier", None) == request  # made once, kept
    assert request["owners"] == [{"identity": owner.identity_hash, "weight": 100}]

    with pytest.raises(IssuerNotReady, match="waiting for the owners"):
        load_owned(db, "My verifier", None, None, owners)

    # the owner approves the founding request; the verifier then authorizes its own signing key, no owner needed
    org = found(request, owner)
    db.save_sigchain(owner.sigchain)
    db.save_sigchain(org)
    issuer = load_owned(db, "My verifier", org.identity_hash, None, owners)
    assert issuer.identity_hash == org.identity_hash and issuer.name == "My verifier"
    assert len(issuer.identity.sigchain.get_active_devices()) == 2  # the org key and the signing device

    holder = Identity.create(name="Alice")
    doc = ClaimDocument.create(holder.identity_hash, "email", "alice@example.com")
    holder.add_claim(doc.claim_id, doc.claim_type, doc.commitment)
    record = holder.sigchain.get_claim(doc.claim_id)
    att = issuer.issue(holder.identity_hash, record, holder.sigchain.head_hash, "email_code", "low")

    resolve = {owner.identity_hash: owner.sigchain}.get
    chain = issuer.identity.sigchain
    assert verify_attestation(att, holder.sigchain, chain, resolve=resolve).ok
    assert not verify_attestation(att, holder.sigchain, chain).ok  # a relying party must be able to look the owners up
    assert verify_revocation(issuer.revoke(att.id, "test"), chain, resolve=resolve).ok

    # a restart finds everything as it was (nothing new to authorize)
    again = load_owned(db, "My verifier", org.identity_hash, None, owners)
    assert again.identity.sigchain.head_hash == chain.head_hash


def test_a_replaced_org_key_stops_this_server_until_it_has_the_new_key():
    db = Storage.memory()
    owner = Identity.create(name="me")
    request = founding_request(db, "V", owner.identity_hash)
    org = found(request, owner)
    db.save_sigchain(owner.sigchain)
    db.save_sigchain(org)
    load_owned(db, "V", org.identity_hash, None, owner.identity_hash)

    new = KeyPair.generate()  # the owners recover the organization's key elsewhere
    ev = propose_governed(RotateMasterEvent, org.head_hash if False else db.get_sigchain(org.identity_hash).head_hash,
                          new_pubkey=new.verify_key.to_hex(), new_encryption_pubkey=new.public_encryption_key.to_hex())
    approve(ev, owner.identity_hash, owner.local_keypair, owner.sigchain.head_hash)
    chain = db.get_sigchain(org.identity_hash)
    chain.append(ev)
    db.save_sigchain(chain)
    with pytest.raises(IssuerNotReady, match="no longer the one"):
        load_owned(db, "V", org.identity_hash, None, owner.identity_hash)


async def test_a_waiting_verifier_says_it_is_not_ready_instead_of_not_found():
    from aiohttp.test_utils import TestClient, TestServer
    from nodetide.verifiers.service import create_pending_app

    app = create_pending_app({"name": "V"}, "waiting for the owners to approve the founding request")
    async with TestClient(TestServer(app)) as client:
        for method, path in [("post", "/api/auth/challenge"), ("get", "/api/verify/issuer"), ("post", "/api/verify/email/start")]:
            resp = await getattr(client, method)(path, headers={"Origin": "https://wallet.example"})
            body = await resp.json()
            assert resp.status == 503 and body["error"] == "issuer_not_ready" and "waiting for the owners" in body["message"]
            assert resp.headers["Access-Control-Allow-Origin"] == "*"  # the browser can read the reason
        assert (await client.get("/api/issuer/request")).status == 200
        assert (await client.get("/health")).status == 200


async def _node_with(*chains):
    """A real node (in-process) holding the given identities' chains."""
    from aiohttp.test_utils import TestServer
    from nodetide.api import create_app

    storage = Storage.memory()
    for chain in chains:
        storage.save_sigchain(chain)
    server = TestServer(create_app(storage=storage))
    await server.start_server()
    return server, f"http://127.0.0.1:{server.port}"


async def test_the_verifier_finds_its_organization_without_being_told_and_ignores_look_alikes():
    import asyncio

    owner = Identity.create(name="me")
    db = Storage.memory()
    request = founding_request(db, "V", owner.identity_hash)

    # a look-alike: the same name and owner, but made with another key
    impostor_db = Storage.memory()
    impostor = found(founding_request(impostor_db, "V", owner.identity_hash), owner)

    server, url = await _node_with(owner.sigchain, impostor)
    try:
        from nodetide.verifiers.issuer import discover_org

        assert await asyncio.to_thread(discover_org, db, url) is None  # not approved yet: nothing matches
        org = found(request, owner)
        server.app["storage"].save_sigchain(org)
        assert await asyncio.to_thread(discover_org, db, url) == org.identity_hash

        # and load_owned does the whole thing from there, remembering the result
        issuer = await asyncio.to_thread(load_owned, db, "V", None, url, owner.identity_hash)
        assert issuer.identity_hash == org.identity_hash and db.get_issuer_org() == org.identity_hash
        again = load_owned(db, "V", None, None, owner.identity_hash)  # a restart needs neither env nor network
        assert again.identity_hash == org.identity_hash
    finally:
        await server.close()


async def test_a_waiting_verifier_restarts_itself_when_the_owners_approve(monkeypatch):
    import asyncio

    from nodetide.verifiers import service

    owner = Identity.create(name="me")
    db = Storage.memory()
    request = founding_request(db, "V", owner.identity_hash)
    server, url = await _node_with(owner.sigchain)
    restarted = asyncio.Event()
    monkeypatch.setattr(service.os, "execv", lambda *a: restarted.set())
    monkeypatch.setattr(db, "close", lambda: None)
    try:
        app = service.create_pending_app(request, "waiting")
        app["storage"], app["node_url"], app["poll_seconds"] = db, url, 0.05
        watcher = asyncio.create_task(service._watch_for_approval(app))
        await asyncio.sleep(0.3)
        assert not restarted.is_set()  # nobody approved yet
        server.app["storage"].save_sigchain(found(request, owner))
        await asyncio.wait_for(restarted.wait(), 5)
        assert db.get_issuer_org() is not None
        watcher.cancel()
    finally:
        await server.close()


async def test_the_node_trusts_the_issuer_the_verifier_publishes_without_a_restart(tmp_path):
    from aiohttp.test_utils import TestClient, TestServer
    from nodetide.api import create_app
    from nodetide.oidc import OIDCClient, OIDCConfig

    issuers = tmp_path / "email-issuer"
    config = OIDCConfig(issuer="http://127.0.0.1:1", clients={"spa": OIDCClient("spa", "Demo", ("https://a.example/cb",))},
                        issuers_file=str(issuers))
    app = create_app(storage=Storage.memory(), oidc_config=config)
    provider = app["oidc"]
    assert "email" not in provider.claim_rules  # trusts nobody until the verifier says who it is
    issuers.write_text("ab" * 32 + "\n")
    provider.refresh_rules()
    assert provider.claim_rules["email"].issuers == frozenset({"ab" * 32})
    assert {"phone", "legal_name"} <= set(provider.claim_rules)
    issuers.write_text("not a hash\n")
    provider.refresh_rules()
    assert provider.claim_rules["email"].issuers == frozenset({"ab" * 32})  # garbage changes nothing
    issuers.write_text("cd" * 32 + "\n")
    provider.refresh_rules()
    assert provider.claim_rules["email"].issuers == frozenset({"cd" * 32})  # a new issuer replaces the old
