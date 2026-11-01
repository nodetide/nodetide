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

    with pytest.raises(IssuerNotReady, match="ISSUER_ORG"):
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
