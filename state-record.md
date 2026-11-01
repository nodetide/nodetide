# The state record: an identity's current state in one DNS TXT record

Status: implemented in Python (`core/state.py`, `core/dns_source.py`, native auth, `nodetide identity dns-record`). Go and Kotlin do not read it yet.

## Why

A sigchain grows; to decide "may this device act for this identity *now*" only the present state matters. The state record carries exactly that, signed by the identity's master key, small enough
for DNS (about 1.2 KB for an identity with three devices, and it does not grow with history: sixty claims and a dozen retired devices added under 200 characters).

## Where

The identity names a domain in a distribution point, `dns:example.org`. The record is a TXT at `<first 32 hex of the identity hash>._nodetide.example.org` (a DNS label is at most 63 characters; the
full hash is inside the record and checked). Whoever controls the domain publishes it; the identity does not have to run a node.

## What it contains

`nt1;` + base64url(deflate(canonical JSON of `{"body", "sig", "lineage"}`)):

* `body`: `id`, `head` (the control chain's head), `n` (its length), `master` (signing and encryption keys), `devices` (key, encryption key, capabilities, added, expiry), the content commitment, `ts`
  (made at) and `exp` (rely on it until).
* `sig`: the master key over `"nodetide-state-v1\0" + body`.
* `lineage`: the genesis event (its hash *is* the identity) and every `rotate_master` since, each signed by the key before it. This is what ties the master key to the identity without the rest of the chain.

## Trust

**DNS needs no trust**: a verifier checks the genesis hash, the rotation signatures, and the master's signature over the body. DNS (or anyone in between) can serve an old record or none; it cannot forge one.

**What it cannot do:**

* *Prove freshness.* A snapshot cannot show that nothing newer exists; `exp` (default 7 days, `--valid-days`) bounds how long it is relied on, and callers can demand a recent `ts` (`max_age`). A revocation
  made after the snapshot is not in it until the record is republished: for sensitive uses prefer the chain, or demand a recent record.
* *Show history.* Claims, attestations and who was revoked when still need the chain. A state authenticates; it does not replace the chain for the OIDC bridge's claims.
* *Cover every identity.* Organizations (owner-governed rotation) and identities that used social recovery or fork resolution would need other chains to verify, so a state cannot be made for them
  (`StateError`: use the chain). More than 12 devices or 8 master rotations: the same.

## Use

* **Publish:** in the web client, **My Identity > DNS state record** (unlock the wallet, enter the domain, choose how long it is valid): it shows the zone-file line, copy buttons, and the list of devices
  the record lists so you can check they are yours. Or from the CLI: `nodetide identity set-distribution -d dns:example.org`, then `nodetide identity dns-record` prints the name and the quoted TXT strings (or `--json`). Republish when devices change and
  before `exp`. Automate it with whatever manages the zone.
* **Node (native auth, `/api/auth/verify` and `/login`):** when there is no chain for the signer, or the stored one is behind (`unknown_chain_head`), the node checks the assertion against a state: one the
  caller supplies (`"state": {...}`), else the one in DNS at a `dns:` point of the identity's own chain, else at a domain the caller names (`"dns": "example.org"`). The assertion's `chain_head` must equal
  the state's head. The stored chain is never changed by this.
* **Limits of the reader:** TXT lookups only, 5 s timeout, up to 8 records examined, results cached for 60 s, only plain public domain names (no IP literals, `.local`, `.internal` and the like).

## The web client

`web/js/state-record.js` builds the record in the browser (canonical JSON, deflate through `CompressionStream`, the master key from the unlocked wallet) and has no dependencies, so a browser test
checks its output with Python's verifier (`tests/test_web_state_record_browser.py`). The chain events, head and Merkle commitment are computed in the browser from the chain the node serves; the device list is
the node's, which is why the card lists the devices for the user to check before the record is published.
