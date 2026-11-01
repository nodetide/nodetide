# Sigchain v2: a control chain that commits to its content

Status: implemented in `python/src/nodetide/core/identity.py` and `core/merkle.py` (reference), `web/js/app.js`. Clean slate: v1
chains are not read. The Go and Android implementations still speak v1 and only agree with v2 for identities that have no
claims (their events are valid v2 control events).

## Why

Everything that decides *who may sign for an identity* (devices, key rotation, recovery, owners) is small and changes rarely.
Everything an identity *says* (claims, preferences, later other statements) is bulk and changes often. In v1 both lived in one
hash chain, so checking a single device signature meant downloading every claim event ever made, and every sign-in sent them all.

v2 splits them into two tracks of one identity (the identity hash is still the hash of the genesis event):

| track | events | linked by | size |
|---|---|---|---|
| **control** | `genesis`, `add_device`, `revoke_device`, `rotate_master`, `set_recovery`, `social_recovery`, `resolve_fork`, `set_distribution`, `set_owners`, `revoke_claim`, `checkpoint` | `prev` = previous *control* event | small |
| **content** | `add_claim`, `set_claim_order` | `prev` = previous *content* event, `seq` = 0, 1, 2, ... | bulk |

`revoke_claim` is a control event on purpose: whether a claim still stands is a trust fact, and a client that has only the control
chain must be able to see every revocation.

## Commitments

Every control event may carry `content: {"count": n, "root": <hex>}`: a commitment to the first `n` content events. The root is
the Merkle root (RFC 6962 style, leaves are `event_hash()` of the content events, `sha256(0x00 || leaf)`, nodes
`sha256(0x01 || left || right)`, the empty tree is `sha256("")`) over content events `0 .. n-1`.

* A control event without `content` commits nothing new (the count stays what it was).
* Every control event created while content events exist **must** commit all of them (`count` = number of content events
  appended before it). The `checkpoint` event exists only to do that: it may be signed by the master key or by a device with
  `manage_claims`.
* Counts never decrease.

## Content events

A content event carries `seq`, `prev` (hash of content event `seq-1`, or null), `control_ref` (hash of the latest control event
when it was signed), `signed_by` and `signature`. It is valid when

1. `seq` and `prev` continue the content chain and `control_ref` names a control event of this chain, not older than the
   previous content event's;
2. its signer is the master key, or a device with `manage_claims`, **as of `control_ref`** (not revoked, not expired);
3. it is covered by the *next* control event after `control_ref`: that event's `count` is greater than `seq`, and `control_ref`'s
   own `count` is not (so every content event falls in exactly one interval, closed by a commitment). Events after the last
   control event are the *tail*: provisionally valid, uncommitted.

Rule 3 is what makes a revoked key harmless: after `revoke_device`, whose commitment fixes the content that existed, an event
signed by the revoked key cannot enter any later commitment.

## Verifying

**Full** (has everything): check the control chain as in v1 plus the commitments (recompute each root) and all content events.

**Light** (has the control chain only): check the control chain (signatures, authorization, structure). A content fact, say
"this identity holds claim C", needs the claim's event and a Merkle path to the root of the first control event after the
event's `control_ref` (`Sigchain.attach_content`). Claim status needs no proof of absence: revocations are control events.
A light chain is marked `partial`; anything about content it has not been given is simply unknown (never "ok").

## Behind, not wrong

If something names a control event the verifier does not have (an assertion's or attestation's `chain_head`, a content event's
`control_ref`), the verifier is **behind**, not facing a bad signature. It reports `stale_state` / "behind" with the missing hash
and fetches the missing control events from other sources (the identity's `distribution_points`, seed nodes); it never treats
the object as valid until the chain it references is in hand. A node may withhold or split; a verifier that knows it is behind
says so and looks elsewhere.

## Not covered

Freshness (proving there is nothing newer than the head a node shows) is not solved here; neither is hiding the commitment of
a content event (the Merkle root is public, the events are fetched on demand and may be kept private by a node).
