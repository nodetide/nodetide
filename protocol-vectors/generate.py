#!/usr/bin/env python3
"""Generate cross-language test vectors for the sigchain (v2) from the Python reference implementation.

    python protocol-vectors/generate.py            # rewrites protocol-vectors/chain-v2.json

Every case is a chain (a list of events, control then content, as the API serves it), the other identities' chains the
verifier is assumed to know (`related`), and what the reference implementation says about it. Go (golang/auth) and the
Kotlin protocol module run the same file and must agree on every case. A case is built so that its verdict is clear by
construction, and the generator checks the reference agrees before writing it.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python" / "src"))

from nodetide.core.crypto import KeyPair  # noqa: E402
from nodetide.core.identity import (  # noqa: E402
    AddDeviceEvent, CheckpointEvent, DeviceCapability as D, GenesisEvent, Identity, IdentityType, RevokeDeviceEvent,
    RotateMasterEvent, SetOwnersEvent, Sigchain, SigchainEvent, SocialRecoveryEvent, approve, propose_governed, sign_recovery,
    AddClaimEvent,
)

NOW = 2_000_000_000          # a fixed "now" for device activity
CASES: list[dict] = []


def chain_events(chain: Sigchain, light: bool = False) -> list[dict]:
    return chain.to_list(light=light)


def describe(chain: Sigchain, resolve) -> dict:
    """What the reference implementation says about a chain that verified."""
    claims = [{"id": c.claim_id, "type": c.claim_type, "revoked": c.revoked_at is not None} for c in chain.get_claims()]
    return {
        "identity": chain.identity_hash,
        "head": chain.head_hash,
        "master": chain.get_current_master_key(),
        "partial": chain.is_partial,
        "control_length": len(chain.events),
        "content_length": len(chain.content),
        "active_devices": sorted(d.pubkey for d in chain.get_active_devices(NOW)),
        "claims": sorted(claims, key=lambda c: c["id"]),
    }


def add(name: str, why: str, chain: Sigchain, related: dict[str, Sigchain] | None = None, valid: bool = True,
        light: bool = False, devices: list[str] | None = None, attach: list[dict] | None = None, check_current: bool = False):
    related = related or {}
    resolve = {h: c for h, c in related.items()}.get
    ok, err = chain.verify(resolve, check_current=check_current)
    assert ok is valid, f"{name}: reference says {ok} ({err}), expected {valid}"
    case = {
        "name": name, "why": why,
        "chain": chain_events(chain, light=light),
        "related": {h: chain_events(c) for h, c in related.items()},
        "check_current": check_current,
        "expect": {"valid": valid},
    }
    if valid:
        shown = chain if not light else Sigchain.from_list(chain.to_list(light=True))
        assert shown.verify(resolve)[0]
        case["expect"].update(describe(shown, resolve))
        for pub in devices or []:
            case["expect"].setdefault("device_status", {})[pub] = shown.device_status(pub)
    else:
        case["expect"]["reference_error"] = err
    if attach:
        case["attach"] = attach
    CASES.append(case)


def person(name="Alice"):
    ident = Identity.create(name=name)
    return ident


# ---------------------------------------------------------------------------------------------------------------------

def personal_basic():
    me = person()
    phone, _ = me.add_device("phone", capabilities=[D.AUTHENTICATE, D.MANAGE_CLAIMS])
    for i, (ctype, commit) in enumerate([("email", "11" * 32), ("phone", "22" * 32), ("email", "33" * 32)]):
        me.add_claim(f"claim-id-{i:010d}", ctype, commit, signer=phone.signing_key if i == 1 else None)
    me.checkpoint()
    me.set_claim_order("email", ["claim-id-0000000002", "claim-id-0000000000"])
    me.revoke_claim("claim-id-0000000001", "gone")
    me.add_device("laptop", capabilities=[D.AUTHENTICATE])
    return me, phone


me, phone = personal_basic()
add("personal-basic", "devices, three claims (one signed by a manage_claims device), a checkpoint, an order, a revocation",
    me.sigchain, devices=[phone.verify_key.to_hex()])

# the same chain as a light client holds it, and with proofs for single claims
light_proofs = []
for seq in range(len(me.sigchain.content)):
    try:
        p = me.sigchain.content_proof(seq)
    except ValueError:
        continue
    light_proofs.append({"seq": seq, "event": p["event"], "proof": p["proof"], "ok": True})
tampered = dict(light_proofs[0]["event"]); tampered["commitment"] = "00" * 32
light_proofs.append({"seq": 0, "event": tampered, "proof": light_proofs[0]["proof"], "ok": False})
light_proofs.append({"seq": 1, "event": light_proofs[0]["event"], "proof": light_proofs[1]["proof"], "ok": False})
add("personal-light", "the same chain without its content (control events only), plus proofs for single content events",
    me.sigchain, light=True, attach=light_proofs)

ident = person("Алекс 😀 \"quoted\" \\ back")
ident.add_device("телефон", capabilities=[D.AUTHENTICATE])
add("non-ascii", "names and labels with non-ASCII characters, quotes and backslashes (canonical JSON escaping)", ident.sigchain)

# ---- content rules
c = person()
c.add_claim("claim-id-0000000000", "email", "aa" * 32)
c.add_device("laptop")                      # commits the claim
bad = Sigchain.from_list(c.sigchain.to_list())
forged_root = AddDeviceEvent.create(c.local_keypair, KeyPair.generate(), "x", bad.head_hash, None,
                                    content={"count": 1, "root": "00" * 32})
bad.append(forged_root)
add("wrong-root", "a validly signed control event whose content root matches nothing", bad, valid=False)

u = person()
u.add_claim("claim-id-0000000000", "email", "bb" * 32)
forgot = Sigchain.from_list(u.sigchain.to_list())
forgot.append(RevokeDeviceEvent.create(u.local_keypair, "ab" * 32, forgot.head_hash))     # does not commit the claim
add("uncommitted-content", "content exists and a control event does not commit it", forgot, valid=False)

t = person()
thief, _ = t.add_device("thief", capabilities=[D.MANAGE_CLAIMS])
old_head = t.sigchain.head_hash
t.revoke_device(thief.verify_key.to_hex(), "lost")
t.sigchain.append(AddClaimEvent.create(thief.signing_key, None, "claim-id-0000000009", "email", "cc" * 32,
                                       seq=0, control_ref=old_head))
add("backdated-by-revoked-device", "a revoked device signs content under a control_ref from before its revocation", t.sigchain, valid=False)

# ---- device revocation fields
r = person()
d1, _ = r.add_device("one", capabilities=[D.SIGN_IDENTITY])
d2, _ = r.add_device("two", capabilities=[D.SIGN_IDENTITY])
r.sigchain.append(RevokeDeviceEvent.create(r.local_keypair, d1.verify_key.to_hex(), r.sigchain.head_hash, "stolen",
                                           untrusted_since=int(time.time()) - 1000))
add("revoke-with-untrusted-since", "a device revoked with a time from which it is untrusted", r.sigchain,
    devices=[d1.verify_key.to_hex(), d2.verify_key.to_hex()])

rot = person()
da, _ = rot.add_device("a", capabilities=[D.SIGN_IDENTITY])
new = KeyPair.generate()
rot.sigchain.append(RotateMasterEvent.create(rot.local_keypair, new, rot.sigchain.head_hash,
                                             revoke_devices="all", untrusted_since=int(time.time()) - 500))
add("rotation-revokes-all", "a master rotation that also revokes every device, from a time", rot.sigchain,
    devices=[da.verify_key.to_hex()])

bad_field = person()
bad_field.sigchain.append(RotateMasterEvent.create(bad_field.local_keypair, KeyPair.generate(), bad_field.sigchain.head_hash,
                                                   revoke_devices="everything"))
add("bad-revoke-field", "revoke_devices that is neither \"all\" nor a list of device keys", bad_field.sigchain, valid=False)

# ---- organizations with owners
owner = person("owner")
other = person("other")


def org(owners, governance=None, approvers=None):
    key = KeyPair.generate()
    genesis = GenesisEvent.create(key, identity_type=IdentityType.ORGANIZATION, name="org",
                                  owners=[{"identity": o.identity_hash, "weight": w} for o, w in owners], governance=governance)
    for o in approvers if approvers is not None else [o for o, _ in owners]:
        approve(genesis, o.identity_hash, o.local_keypair, o.sigchain.head_hash)
    return Sigchain(events=[genesis]), key


chain_o, key_o = org([(owner, 100)])
chain_o.append(AddDeviceEvent.create(key_o, KeyPair.generate(), "signer", chain_o.head_hash, [D.SIGN_IDENTITY]))
add("org-self-run", "an organization owned by one identity, running itself with its own key", chain_o,
    related={owner.identity_hash: owner.sigchain})

no_owner = Sigchain(events=list(chain_o.events))
add("org-needs-owner-chains", "the same organization cannot be checked without the owners' chains", no_owner, related={}, valid=False)

missing, _ = org([(owner, 60), (other, 40)], approvers=[owner])
add("org-founding-needs-everyone", "a founding approval missing one owner", missing,
    related={owner.identity_hash: owner.sigchain, other.identity_hash: other.sigchain}, valid=False)

chain_r, key_r = org([(owner, 100)])
dev = KeyPair.generate()
chain_r.append(AddDeviceEvent.create(key_r, dev, "signer", chain_r.head_hash, [D.SIGN_IDENTITY]))
replacement = KeyPair.generate()
event = propose_governed(RotateMasterEvent, chain_r.head_hash, new_pubkey=replacement.verify_key.to_hex(),
                         new_encryption_pubkey=replacement.public_encryption_key.to_hex(), revoke_devices="all", untrusted_since=int(time.time()) - 100)
approve(event, owner.identity_hash, owner.local_keypair, owner.sigchain.head_hash)
chain_r.append(event)
add("org-governed-replacement", "the owners replace the organization's key and revoke all its devices in one event", chain_r,
    related={owner.identity_hash: owner.sigchain}, devices=[dev.verify_key.to_hex()])

unapproved = Sigchain(events=list(chain_r.events[:-1]))
bare = propose_governed(RotateMasterEvent, unapproved.head_hash, new_pubkey=replacement.verify_key.to_hex(),
                        new_encryption_pubkey=replacement.public_encryption_key.to_hex())
unapproved.append(bare)
add("org-governed-without-approval", "a governed rotation with no owner approval", unapproved,
    related={owner.identity_hash: owner.sigchain}, valid=False)

chain_m, key_m = org([(owner, 100)], governance="managed")
chain_m.append(AddDeviceEvent.create(key_m, KeyPair.generate(), "signer", chain_m.head_hash, [D.SIGN_IDENTITY]))
add("org-managed-device-by-org-key", "in a managed organization the organization's own key may not add a device", chain_m,
    related={owner.identity_hash: owner.sigchain}, valid=False)

chain_m2, _ = org([(owner, 100)], governance="managed")
dev_event = propose_governed(AddDeviceEvent, chain_m2.head_hash, device_pubkey=dev.verify_key.to_hex(),
                             device_encryption_pubkey=dev.public_encryption_key.to_hex(), label="signer", capabilities=["sign_identity"])
approve(dev_event, owner.identity_hash, owner.local_keypair, owner.sigchain.head_hash)
chain_m2.append(dev_event)
add("org-managed-device-by-owners", "in a managed organization the owners add the device", chain_m2,
    related={owner.identity_hash: owner.sigchain}, devices=[dev.verify_key.to_hex()])

# ---- social recovery
victim = person("victim")
tr = [person(f"t{i}") for i in range(3)]
victim.set_recovery([t.identity_hash for t in tr], 2)
new_key = KeyPair.generate()


def recovery_event(signers):
    prev = victim.sigchain.head_hash
    sigs = [sign_recovery(t.identity_hash, t.local_keypair, t.sigchain.head_hash, victim.identity_hash, prev,
                          new_key.verify_key.to_hex(), new_key.public_encryption_key.to_hex()) for t in signers]
    ev = SocialRecoveryEvent(type=None, timestamp=int(time.time()), prev=prev, signature="", signed_by=new_key.verify_key.to_hex(),
                             new_pubkey=new_key.verify_key.to_hex(), new_encryption_pubkey=new_key.public_encryption_key.to_hex(),
                             recovery_signatures=sigs)
    ev.signature = new_key.sign_hex(json.dumps(ev.signable_dict(), sort_keys=True, separators=(",", ":")).encode())
    return ev


trustee_chains = {t.identity_hash: t.sigchain for t in tr}
enough = Sigchain.from_list(victim.sigchain.to_list())
enough.append(recovery_event(tr[:2]))
add("recovery-enough", "two of three trustees restore the identity to a new key", enough, related=trustee_chains)
few = Sigchain.from_list(victim.sigchain.to_list())
few.append(recovery_event(tr[:1]))
add("recovery-too-few", "one of three trustees is not enough", few, related=trustee_chains, valid=False)
add("recovery-needs-trustee-chains", "the trustees' chains are needed to check the signatures", enough, related={}, valid=False)

out = ROOT / "protocol-vectors" / "chain-v2.json"
out.write_text(json.dumps({"format": "nodetide-chain-vectors", "version": 2, "now": NOW, "cases": CASES}, indent=1, sort_keys=True) + "\n")
print(f"wrote {len(CASES)} cases to {out.relative_to(ROOT)}")
