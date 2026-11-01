"""The OIDC bridge releases verified claims (email, legal name) to applications that ask for them."""

from __future__ import annotations

import time

import pytest
from aiohttp.test_utils import TestClient, TestServer

from nodetide.api import create_app
from nodetide.core.claims import (
    PROOF_VERIFIERS, Attestation, AttestationRevocation, ClaimDocument,
)
from nodetide.core.identity import DeviceCapability, Identity, IdentityType, SocialRecoveryEvent
from nodetide.core.relying_party import ClaimRule, evaluate_claim, recovered_since
from nodetide.core.storage import Storage
from nodetide.oidc import ConfigError, OIDCConfig
from nodetide.verifiers import EmailVerifier, NodeIssuer
from nodetide.verifiers.mail import MemorySender
from tests.test_eidas import World
from tests.test_oidc_bridge import (
    FakeNetwork, SPA, SPA_REDIRECT, Env, code_from, decode_id_token, exchange, get_status, sign, start_login, submit,
)

D = DeviceCapability
ADDRESS = "maria@example.com"
SCOPES = "openid profile email"


class Holder:
    """Maria: a holder with a device, an email claim (attested by the node) and a legal-name
    claim (backed by a qualified signature from the synthetic CA)."""

    def __init__(self, storage: Storage, verifier: EmailVerifier, world: World):
        self.world, self.storage, self.verifier = world, storage, verifier
        self.identity = world.holder
        self.device, _ = self.identity.add_device("phone", capabilities=[D.AUTHENTICATE])
        self.email_doc = ClaimDocument.create(self.identity.identity_hash, "email", ADDRESS)
        self.identity.add_claim(self.email_doc.claim_id, "email", self.email_doc.commitment)
        storage.save_sigchain(self.identity.sigchain)

    def email_attestation(self, issuer: NodeIssuer | None = None, assurance: str = "low") -> Attestation:
        record = self.identity.sigchain.get_claim(self.email_doc.claim_id)
        return (issuer or self.verifier.issuer).issue(
            self.identity.identity_hash, record, self.identity.sigchain.head_hash, "email_code", assurance)

    def name_attestation(self) -> Attestation:
        return self.world.attest()

    def email_presentation(self, **kw) -> dict:
        issuer = kw.get("issuer") or self.verifier.issuer
        return {"document": self.email_doc.to_dict(), "attestation": (kw.get("attestation") or self.email_attestation(issuer)).to_dict(),
                "issuer_sigchain": issuer.identity.sigchain.to_list()}

    def name_presentation(self, attestation=None, document=None) -> dict:
        return {"document": (document or self.world.doc).to_dict(), "attestation": (attestation or self.name_attestation()).to_dict()}


@pytest.fixture
async def bridge():
    storage = Storage.memory()
    world = World()
    # the verifier is an independent service with its own storage; the bridge trusts it only because it is named
    verifier_storage = Storage.memory()
    verifier = EmailVerifier(verifier_storage, NodeIssuer.load_or_create(verifier_storage, "Independent Verifier"), MemorySender())
    net = FakeNetwork()
    config = OIDCConfig(issuer="https://bridge.test", clients={SPA.client_id: SPA},
                        seed_nodes=["https://seed.example.net"],
                        email_issuers=[verifier.issuer.identity_hash], notary_issuers=[verifier.issuer.identity_hash])
    app = create_app(storage=storage, oidc_config=config, oidc_fetch=net.fetch,
                     eidas_policy=world.policy, auth_audience="https://node.test")

    async def no_background() -> None:
        return None

    app["oidc"].fetcher.start = no_background
    try:
        async with TestClient(TestServer(app)) as client:
            env = Env(client, storage, net, app["oidc"])
            env.holder = Holder(storage, verifier, world)
            yield env
    finally:
        PROOF_VERIFIERS.pop("eidas_qes", None)


async def sign_in(env: Env, presentations, scope: str = SCOPES, *, extra=None, holder: Holder | None = None):
    """Run a whole sign-in; returns (submit response body, id_token claims, userinfo)."""
    holder = holder or env.holder
    attempt_id, secret, verifier = await start_login(env, scope=scope)
    assertion = await sign(env, attempt_id, holder.identity, holder.device)
    body = {"presentations": presentations, **(extra or {})}
    resp = await submit(env, attempt_id, assertion, **body)
    payload = await resp.json()
    assert resp.status == 200, payload
    status = await get_status(env, attempt_id, secret)
    tokens = await (await exchange(env, code_from(status), verifier)).json()
    claims = await decode_id_token(env, tokens["id_token"])
    info = await (await env.client.get("/oidc/userinfo", headers={"Authorization": f"Bearer {tokens['access_token']}"})).json()
    return payload, claims, info


# --- what gets released -------------------------------------------------------------------------------------------


async def test_verified_email_is_released(bridge):
    h = bridge.holder
    payload, claims, info = await sign_in(bridge, [h.email_presentation()])
    assert claims["email"] == ADDRESS and claims["email_verified"] is True
    assert info["email"] == ADDRESS and info["sub"] == h.identity.identity_hash
    assert payload["claims"]["released"] == [{"claim_type": "email", "assurance": "low", "method": "email_code"}]
    assert "legal_name" not in str(payload["claims"]["released"])


async def test_qualified_signature_releases_the_verified_name(bridge):
    h = bridge.holder
    payload, claims, info = await sign_in(bridge, [h.name_presentation()])
    assert (claims["given_name"], claims["family_name"], claims["name"]) == ("Maria", "Ivanova", "Maria Ivanova")
    assert claims["name_verified"] is True
    (verified,) = claims["verified_claims"]
    assert verified["verification"]["trust_framework"] == "eidas"
    assert verified["verification"]["assurance_level"] == "high"
    assert verified["verification"]["time"].endswith("Z")
    assert verified["claims"] == {"given_name": "Maria", "family_name": "Ivanova"}
    assert info["name"] == "Maria Ivanova" and "verified_claims" in info


async def test_both_claims_together(bridge):
    h = bridge.holder
    payload, claims, _ = await sign_in(bridge, [h.email_presentation(), h.name_presentation()])
    assert claims["email"] == ADDRESS and claims["name"] == "Maria Ivanova"
    assert {r["claim_type"] for r in payload["claims"]["released"]} == {"email", "legal_name"}


async def test_nothing_is_released_that_the_scope_did_not_ask_for(bridge):
    h = bridge.holder
    payload, claims, info = await sign_in(bridge, [h.email_presentation(), h.name_presentation()], scope="openid")
    for key in ("email", "email_verified", "given_name", "name", "verified_claims"):
        assert key not in claims and key not in info
    assert payload["claims"]["released"] == [] and payload["claims"]["ignored"] == 2

    payload, claims, _ = await sign_in(bridge, [h.email_presentation(), h.name_presentation()], scope="openid email")
    assert claims["email"] == ADDRESS and "name" not in claims or claims.get("name_verified") is False


async def test_without_presentations_the_name_is_labelled_self_asserted(bridge):
    _, claims, _ = await sign_in(bridge, [])
    assert "email" not in claims
    assert claims["name"] == "Maria" and claims["name_verified"] is False  # from the genesis event


# --- what is refused -----------------------------------------------------------------------------------------------------


async def rejected(bridge, presentation, scope=SCOPES):
    payload, claims, _ = await sign_in(bridge, [presentation], scope=scope)
    assert payload["claims"]["released"] == []  # sign-in still succeeds; just nothing is released
    return payload["claims"]["rejected"], claims


async def test_untrusted_issuer_is_not_believed(bridge):
    h = bridge.holder
    stranger = NodeIssuer.load_or_create(Storage.memory(), "Some Other Verifier")
    bridge.storage.save_sigchain(stranger.identity.sigchain)
    rej, claims = await rejected(bridge, h.email_presentation(attestation=h.email_attestation(issuer=stranger), issuer=stranger))
    assert rej == [{"claim_type": "email", "code": "issuer_not_accepted"}] and "email" not in claims


async def test_trusted_issuers_can_be_added_by_the_operator(bridge):
    h = bridge.holder
    stranger = NodeIssuer.load_or_create(Storage.memory(), "Partner Verifier")
    bridge.storage.save_sigchain(stranger.identity.sigchain)
    rules = dict(bridge.provider.claim_rules)
    rules["email"] = ClaimRule("email", issuers=rules["email"].issuers | {stranger.identity_hash})
    bridge.provider.claim_rules = rules
    _, claims, _ = await sign_in(bridge, [h.email_presentation(attestation=h.email_attestation(issuer=stranger), issuer=stranger)])
    assert claims["email"] == ADDRESS


async def test_revoked_attestation_is_not_believed(bridge):
    h = bridge.holder
    att = h.email_attestation()
    bridge.storage.save_attestation_revocation(att.id, AttestationRevocation.create(
        h.verifier.issuer.identity_hash, h.verifier.issuer.device_key, att.id, "mistake").to_dict())
    rej, _ = await rejected(bridge, h.email_presentation(attestation=att))
    assert rej == [{"claim_type": "email", "code": "revoked"}]


async def test_a_document_that_is_not_the_claim_is_rejected(bridge):
    h = bridge.holder
    other = ClaimDocument(h.email_doc.identity, h.email_doc.claim_id, "email", "someone-else@example.com", h.email_doc.salt)
    rej, _ = await rejected(bridge, {"document": other.to_dict(), "attestation": h.email_attestation().to_dict()})
    assert rej == [{"claim_type": "email", "code": "claim_mismatch"}]


async def test_name_must_match_the_certificate(bridge):
    h = bridge.holder
    w = h.world
    liar = ClaimDocument.create(h.identity.identity_hash, "legal_name", {"given_name": "Petar", "family_name": "Petrov"})
    h.identity.add_claim(liar.claim_id, "legal_name", liar.commitment)
    bridge.storage.save_sigchain(h.identity.sigchain)
    from nodetide.eidas.issue import build_eidas_attestation
    att = build_eidas_attestation(h.identity.sigchain, h.identity.sigchain.get_claim(liar.claim_id), w.signer)
    rej, claims = await rejected(bridge, h.name_presentation(attestation=att, document=liar))
    assert rej == [{"claim_type": "legal_name", "code": "name_mismatch"}] and claims.get("name_verified") is False


async def test_low_assurance_does_not_satisfy_a_legal_name_rule(bridge):
    h = bridge.holder
    org = NodeIssuer.load_or_create(Storage.memory(), "Name Checker")
    bridge.storage.save_sigchain(org.identity.sigchain)
    record = h.identity.sigchain.get_claim(h.world.doc.claim_id)
    weak = org.issue(h.identity.identity_hash, record, h.identity.sigchain.head_hash, "manual", "low")
    rules = dict(bridge.provider.claim_rules)
    rules["legal_name"] = ClaimRule("legal_name", issuers=frozenset({org.identity_hash}), allow_proof=True, min_assurance="high")
    bridge.provider.claim_rules = rules
    rej, _ = await rejected(bridge, h.name_presentation(attestation=weak))
    assert rej == [{"claim_type": "legal_name", "code": "assurance_too_low"}]


async def test_malformed_and_foreign_presentations_release_nothing(bridge):
    h = bridge.holder
    other_world = World()
    other = Holder(Storage.memory(), h.verifier, other_world)  # another identity's claim
    payload, claims, _ = await sign_in(bridge, [
        {"document": "nonsense", "attestation": {}},
        {},
        other.name_presentation(),
    ])
    codes = [r["code"] for r in payload["claims"]["rejected"]]
    assert codes.count("invalid_presentation") == 2 and "wrong_identity" in codes
    assert payload["claims"]["released"] == []


async def test_presentation_limits(bridge):
    h = bridge.holder
    attempt_id, _, _ = await start_login(bridge, scope=SCOPES)
    assertion = await sign(bridge, attempt_id, h.identity, h.device)
    for bad in ("nope", [1], [h.email_presentation()] * 6):
        resp = await submit(bridge, attempt_id, assertion, presentations=bad)
        assert resp.status == 400, bad


async def test_unsuitable_presentation_never_blocks_sign_in(bridge):
    h = bridge.holder
    attempt_id, secret, verifier = await start_login(bridge, scope=SCOPES)
    assertion = await sign(bridge, attempt_id, h.identity, h.device)
    resp = await submit(bridge, attempt_id, assertion, presentations=[{"document": 1, "attestation": 2}])
    assert resp.status == 200 and (await get_status(bridge, attempt_id, secret))["status"] == "approved"


# --- the challenge and the responses ---------------------------------------------------------------------------------


async def test_challenge_tells_the_app_what_is_acceptable(bridge):
    h = bridge.holder
    attempt_id, _, _ = await start_login(bridge, scope=SCOPES)
    display = (await (await bridge.client.get(f"/oidc/login/{attempt_id}/challenge")).json())["display"]
    by_type = {c["claim_type"]: c for c in display["claims_requested"]}
    assert set(by_type) == {"email", "legal_name"}
    assert by_type["email"]["accepted_issuers"] == [h.verifier.issuer.identity_hash]
    assert by_type["legal_name"]["accepts_proof"] is True and by_type["legal_name"]["min_assurance"] == "high"

    only_openid, _, _ = await start_login(bridge, scope="openid")
    display = (await (await bridge.client.get(f"/oidc/login/{only_openid}/challenge")).json())["display"]
    assert display["claims_requested"] == []


async def test_claim_values_never_appear_in_sign_in_responses(bridge):
    h = bridge.holder
    attempt_id, secret, _ = await start_login(bridge, scope=SCOPES)
    assertion = await sign(bridge, attempt_id, h.identity, h.device)
    resp = await submit(bridge, attempt_id, assertion, presentations=[h.email_presentation(), h.name_presentation()])
    text = await resp.text()
    status_text = str(await get_status(bridge, attempt_id, secret))
    for secret_value in (ADDRESS, "Ivanova", h.email_doc.salt):
        assert secret_value not in text and secret_value not in status_text


async def test_presentations_survive_the_wait_for_an_unknown_identity(bridge):
    h = bridge.holder
    # the bridge does not know this identity yet: it must fetch it, then still release the claims
    with bridge.storage.transaction() as cur:
        cur.execute("DELETE FROM sigchains WHERE identity_hash = ?", (h.identity.identity_hash,))
        cur.execute("DELETE FROM explorer_identities WHERE identity_hash = ?", (h.identity.identity_hash,))
    attempt_id, secret, verifier = await start_login(bridge, scope=SCOPES)
    assertion = await sign(bridge, attempt_id, h.identity, h.device)
    resp = await submit(bridge, attempt_id, assertion, presentations=[h.email_presentation()])
    assert resp.status == 202

    bridge.net.publish(h.identity)
    await bridge.provider.fetcher.run_once()
    status = await get_status(bridge, attempt_id, secret)
    assert status["status"] == "approved"
    tokens = await (await exchange(bridge, code_from(status), verifier)).json()
    assert (await decode_id_token(bridge, tokens["id_token"]))["email"] == ADDRESS


# --- the rules themselves --------------------------------------------------------------------------------------------------


def test_default_rules_follow_what_the_node_can_verify():
    from nodetide.oidc.handlers import default_claim_rules

    class FakeApp(dict):
        pass

    config = OIDCConfig(issuer="https://bridge.test", clients={})
    assert default_claim_rules(FakeApp(), config) == {}  # nothing to verify with, nothing offered

    app = FakeApp(eidas_policy=object())
    assert set(default_claim_rules(app, config)) == {"legal_name"}
    assert default_claim_rules(app, config)["legal_name"].allow_proof

    trusted = OIDCConfig(issuer="https://bridge.test", clients={}, trusted_issuers=["a" * 64])
    rules = default_claim_rules(FakeApp(), trusted)
    assert set(rules) == {"email", "phone", "legal_name", "birthdate", "age_over_18"} and not rules["legal_name"].allow_proof
    assert rules["legal_name"].min_assurance == "high" and rules["phone"].issuers == frozenset({"a" * 64})

    notary = OIDCConfig(issuer="https://bridge.test", clients={}, notary_issuers=["b" * 64])
    rules = default_claim_rules(FakeApp(), notary)
    assert set(rules) == {"legal_name", "birthdate", "age_over_18"}  # a notary says nothing about email or phone
    assert all(r.min_assurance == "high" and r.issuers == frozenset({"b" * 64}) for r in rules.values())


def test_configuration_is_validated():
    with pytest.raises(ConfigError):
        OIDCConfig(issuer="https://bridge.test", clients={}, trusted_issuers=["not-a-hash"])
    with pytest.raises(ConfigError):
        OIDCConfig(issuer="https://bridge.test", clients={}, name_match="sloppy")
    with pytest.raises(ValueError):
        ClaimRule("email", min_assurance="maximum")


def test_recovered_since_only_counts_recoveries_after_the_attestation():
    holder = Identity.create()
    head_before = holder.sigchain.head_hash
    holder.add_device("phone")
    head_between = holder.sigchain.head_hash
    new = Identity.create()
    holder.sigchain.append(SocialRecoveryEvent(
        type=None, timestamp=int(time.time()), prev=holder.sigchain.head_hash, signature="",
        signed_by=new.local_keypair.verify_key.to_hex(), new_pubkey=new.local_keypair.verify_key.to_hex(),
        new_encryption_pubkey=new.local_keypair.public_encryption_key.to_hex(), recovery_signatures=[]))
    assert recovered_since(holder.sigchain, head_before) and recovered_since(holder.sigchain, head_between)
    assert not recovered_since(holder.sigchain, holder.sigchain.head_hash)  # attested after the recovery

    plain = Identity.create()
    assert not recovered_since(plain.sigchain, plain.sigchain.head_hash)


def test_rules_enforce_age_and_method():
    holder = Identity.create()
    doc = ClaimDocument.create(holder.identity_hash, "email", "a@example.com")
    holder.add_claim(doc.claim_id, "email", doc.commitment)
    issuer = NodeIssuer.load_or_create(Storage.memory(), "V")
    att = issuer.issue(holder.identity_hash, holder.sigchain.get_claim(doc.claim_id), holder.sigchain.head_hash, "email_code", "low")
    base = ClaimRule("email", issuers=frozenset({issuer.identity_hash}))
    ok = evaluate_claim(base, doc, att, holder.sigchain, issuer.identity.sigchain)
    assert ok.ok and ok.claim.value == "a@example.com" and ok.claim.issuer == issuer.identity_hash

    old = ClaimRule("email", issuers=base.issuers, max_age_days=1)
    later = att.issued_at + 3 * 86400
    assert evaluate_claim(old, doc, att, holder.sigchain, issuer.identity.sigchain, now=later).code == "too_old"
    picky = ClaimRule("email", issuers=base.issuers, methods=frozenset({"phone_code"}))
    assert evaluate_claim(picky, doc, att, holder.sigchain, issuer.identity.sigchain).code == "method_not_accepted"
    assert evaluate_claim(base, doc, att, holder.sigchain, None).code == "unknown_issuer"
    wrong = ClaimRule("phone", issuers=base.issuers)
    assert evaluate_claim(wrong, doc, att, holder.sigchain, issuer.identity.sigchain).code == "wrong_claim_type"


async def test_nothing_is_trusted_unless_named(bridge):
    """A bridge trusts no email issuer by default, including any verifier that happens to run beside it."""
    from nodetide.oidc.handlers import default_claim_rules

    app = bridge.client.app
    config = OIDCConfig(issuer="https://b.example.org", clients={})
    assert "email" not in default_claim_rules(app, config)
    named = OIDCConfig(issuer="https://b.example.org", clients={}, email_issuers=["a" * 64])
    rules = default_claim_rules(app, named)
    assert rules["email"].issuers == frozenset({"a" * 64}) and "phone" not in rules
    phones = OIDCConfig(issuer="https://b.example.org", clients={}, phone_issuers=["c" * 64])
    rules = default_claim_rules(app, phones)
    assert rules["phone"].issuers == frozenset({"c" * 64}) and "email" not in rules


def test_email_issuers_come_from_the_environment_and_must_be_hashes(monkeypatch):
    from nodetide.oidc.config import ConfigError

    monkeypatch.setenv("NODETIDE_OIDC_ISSUER", "https://b.example.org")
    monkeypatch.setenv("NODETIDE_OIDC_EMAIL_ISSUERS", f" {'A' * 64} , {'b' * 64} ")
    assert OIDCConfig.from_env().email_issuers == ["a" * 64, "b" * 64]
    monkeypatch.setenv("NODETIDE_OIDC_EMAIL_ISSUERS", "not-a-hash")
    with pytest.raises(ConfigError):
        OIDCConfig.from_env()


async def test_birthdate_and_age_are_released_only_when_asked_for_and_presented(bridge):
    h = bridge.holder
    born = ClaimDocument.create(h.identity.identity_hash, "birthdate", "1985-06-15")
    adult = ClaimDocument.create(h.identity.identity_hash, "age_over_18", True)
    for doc in (born, adult):
        h.identity.add_claim(doc.claim_id, doc.claim_type, doc.commitment)
    bridge.storage.save_sigchain(h.identity.sigchain)
    issuer = h.verifier.issuer

    def presentation(doc):
        record = h.identity.sigchain.get_claim(doc.claim_id)
        att = issuer.issue(h.identity.identity_hash, record, h.identity.sigchain.head_hash, "eidas_notary", "high",
                           {"source": "eidas_qes", "qscd": True})
        return {"document": doc.to_dict(), "attestation": att.to_dict(), "issuer_sigchain": issuer.identity.sigchain.to_list()}

    both = [presentation(born), presentation(adult)]
    _, claims, info = await sign_in(bridge, both, scope="openid birthdate age_over_18")
    assert claims["birthdate"] == "1985-06-15" and claims["age_over_18"] is True and info["birthdate"] == "1985-06-15"
    frameworks = {v["verification"]["trust_framework"] for v in claims["verified_claims"]}
    assert frameworks == {"eidas"}
    # the person may prove "over 18" without the date
    _, claims, _ = await sign_in(bridge, [presentation(adult)], scope="openid birthdate age_over_18")
    assert claims["age_over_18"] is True and "birthdate" not in claims
    # presented but not asked for: nothing is released
    _, claims, _ = await sign_in(bridge, both, scope="openid")
    assert "birthdate" not in claims and "age_over_18" not in claims
    _, claims, _ = await sign_in(bridge, both, scope="openid age_over_18")
    assert claims["age_over_18"] is True and "birthdate" not in claims


# --- a light presenter: control chain + a Merkle path for the one claim shown ---------------------------------


async def test_a_claim_is_proven_with_a_merkle_path_when_the_node_holds_only_the_control_chain(bridge):
    from nodetide.core.identity import Sigchain

    h = bridge.holder
    h.identity.checkpoint()                                   # commit the claims to the control chain
    bridge.storage.save_sigchain(Sigchain.from_list(h.identity.sigchain.to_list(light=True)))
    seq = next(i for i, e in enumerate(h.identity.sigchain.content) if getattr(e, "claim_id", None) == h.email_doc.claim_id)
    proof = h.identity.sigchain.content_proof(seq)
    presentation = {**h.email_presentation(), "claim_event": proof["event"], "claim_proof": proof["proof"]}

    payload, claims, info = await sign_in(bridge, [presentation])
    assert claims["email"] == ADDRESS and claims["email_verified"] is True
    assert payload["claims"]["released"] == [{"claim_type": "email", "assurance": "low", "method": "email_code"}]


async def test_a_wrong_or_missing_proof_releases_nothing(bridge):
    from nodetide.core.identity import Sigchain

    h = bridge.holder
    h.identity.checkpoint()
    bridge.storage.save_sigchain(Sigchain.from_list(h.identity.sigchain.to_list(light=True)))
    seq = next(i for i, e in enumerate(h.identity.sigchain.content) if getattr(e, "claim_id", None) == h.email_doc.claim_id)
    proof = h.identity.sigchain.content_proof(seq)

    wrong = {**h.email_presentation(), "claim_event": proof["event"], "claim_proof": ["00" * 32] + proof["proof"][1:]}
    payload, claims, _ = await sign_in(bridge, [wrong])
    assert "email" not in claims and payload["claims"]["rejected"][0]["code"] == "bad_claim_proof"

    payload, claims, _ = await sign_in(bridge, [h.email_presentation()])      # no proof: the node cannot see the claim
    assert "email" not in claims and payload["claims"]["rejected"][0]["code"] in ("unknown_claim", "claim_mismatch")
