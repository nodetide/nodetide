# Distributed Identity System

## Overview

A transport-agnostic identity system designed for delay-tolerant messaging across multiple delivery mechanisms (TCP/DNS, TCP/mDNS, Bluetooth, mesh radio, sneakernet).

## Core Principles

- **Identity = hash(sigchain)** - Stable identifier derived from append-only event log
- **Master/sub-key hierarchy** - Separate identity continuity from operational keys
- **Append-only sigchain** - Embedded in protocol, no history rewriting
- **Social recovery** - Threshold of trusted contacts can recover compromised identity

## Key Hierarchy

```
Master Key (identity)
├── signs → Device Key A (phone)
├── signs → Device Key B (laptop)
├── signs → Device Key C (agent/bot)
└── signs → Key Rotation Record → New Master Key
                                   ├── signs → Device Key D
                                   └── ...
```

> **v2:** the sigchain is now two tracks, a small control chain that commits to bulk content, so a verifier can skip the content. See `sigchain-v2.md`.

## Sigchain Structure

The sigchain is an append-only log of signed events:

```
┌─────────────────────────────────────────────────────────┐
│ Event 0: GENESIS                                        │
│   pubkey: <master_pubkey_0>                             │
│   sig: <self-signed>                                    │
├─────────────────────────────────────────────────────────┤
│ Event 1: SET_RECOVERY (optional, can be added anytime)  │
│   recovery_threshold: 3                                 │
│   recovery_trustees: [alice, bob, carol, dave, eve]     │
│   prev: hash(event_0)                                   │
│   sig: <signed by master_0>                             │
├─────────────────────────────────────────────────────────┤
│ Event 2: ADD_DEVICE                                     │
│   device_pubkey: <phone_key>                            │
│   label: "phone"                                        │
│   expires: 2026-06-01 (optional)                        │
│   prev: hash(event_1)                                   │
│   sig: <signed by master_0>                             │
├─────────────────────────────────────────────────────────┤
│ Event 3: REVOKE_DEVICE                                  │
│   device_pubkey: <phone_key>                            │
│   reason: "lost"                                        │
│   prev: hash(event_2)                                   │
│   sig: <signed by master_0>                             │
├─────────────────────────────────────────────────────────┤
│ Event 4: ROTATE_MASTER                                  │
│   new_pubkey: <master_pubkey_1>                         │
│   prev: hash(event_3)                                   │
│   sig: <signed by master_0>                             │
├─────────────────────────────────────────────────────────┤
│ Event 5: SOCIAL_RECOVERY                                │
│   new_pubkey: <master_pubkey_2>                         │
│   prev: hash(event_4)                                   │
│   recovery_sigs: [                                      │
│     {trustee: alice, sig: ...},                         │
│     {trustee: bob, sig: ...},                           │
│     {trustee: dave, sig: ...}                           │
│   ]                                                     │
└─────────────────────────────────────────────────────────┘

Identity = hash(event_0) = "7f3a8b..." (stable forever)
```

## Event Types

| Event | Signed by | Purpose |
|-------|-----------|---------|
| `GENESIS` | self | Create identity (minimal, no trustees required) |
| `SET_RECOVERY` | master | Add/update recovery trustees (optional, anytime) |
| `SET_DISTRIBUTION` | master | Update distribution points (where to reach this identity) |
| `ADD_DEVICE` | master | Authorize sub-key |
| `REVOKE_DEVICE` | master | Explicit revocation |
| `ROTATE_MASTER` | old master | Normal key rotation |
| `SOCIAL_RECOVERY` | threshold of trustees | Emergency recovery |
| `ADD_CLAIM` | master or device with `manage_claims` | Commit to a claim about this identity (value stays off-chain) |
| `REVOKE_CLAIM` | master or device with `manage_claims` | Withdraw a claim |
| `SET_CLAIM_ORDER` | master or device with `manage_claims` | Say which claims of one type come first; the first is the holder's default |

## Revocation

Two mechanisms:

1. **Explicit revocation** - `REVOKE_DEVICE` event signed by master key
2. **Expiration** - Optional `expires` timestamp on device keys

## Distribution Points

Distribution points are URIs where an identity can be reached. They help with initial contact and routing.

### Setting Distribution Points

Distribution points can be set at identity creation or updated later:

**At creation (in GENESIS):**
```
GENESIS = {
  pubkey: <master_pubkey>,
  distribution_points: [
    "https://relay.example.com/users/alice",
    "dtn://node.local:4556",
    "mesh://abc123"
  ],
  sig: <self-signed>
}
```

**Update later:**
```
SET_DISTRIBUTION = {
  distribution_points: [
    "https://new-relay.example.com/alice",
    "dtn://home.local:4556"
  ],
  prev: <hash>,
  sig: <signed by master>
}
```

### URI Formats

Distribution points use standard URI formats:

| Scheme | Example | Use |
|--------|---------|-----|
| `https://` | `https://relay.example.com/users/alice` | Web relay |
| `wss://` | `wss://relay.example.com/ws` | WebSocket relay |
| `mailto:` | `mailto:alice@example.com` | Email (SMTP) |
| `dtn://` | `dtn://node.local:4556` | DTN node (TCP) |
| `mesh://` | `mesh://abc123` | Mesh network address |
| `bt://` | `bt://AA:BB:CC:DD:EE:FF` | Bluetooth address |

### Email Transport (SMTP)

Email provides a ubiquitous, delay-tolerant transport layer. Messages are encoded in request/response email format.

**Request Email Format:**
```
From: sender@example.com
To: recipient@example.com
Subject: [NODETIDE] <message-type> <message-id-short>
Content-Type: application/json; charset=utf-8
X-Nodetide-Version: 1
X-Nodetide-Type: <bundle-type>
X-Nodetide-Sender: <sender-identity-hash>

<JSON-encoded bundle>
```

**Response Email Format:**
```
From: recipient@example.com
To: sender@example.com
Subject: Re: [NODETIDE] <message-type> <message-id-short>
Content-Type: application/json; charset=utf-8
In-Reply-To: <original-message-id>
X-Nodetide-Version: 1
X-Nodetide-Type: ack
X-Nodetide-Sender: <recipient-identity-hash>

<JSON-encoded response/ack>
```

**Message Types in Subject:**
| Type | Subject Example |
|------|-----------------|
| Sigchain sync | `[NODETIDE] sigchain 7f3a8b` |
| Private message | `[NODETIDE] message a2c4d6` |
| Delivery ack | `[NODETIDE] ack b3e5f7` |
| Revocation | `[NODETIDE] revocation c4f6g8` |

**Large Content:**

For content exceeding email size limits (~25MB typical):
1. Send `ContentAnnounce` via email with available fetch methods
2. Recipient requests chunks via separate emails or alternative transport
3. Or use multipart MIME with chunked attachments

**Security Considerations:**
- Email transport is public - always encrypt sensitive content at message layer
- SPF/DKIM/DMARC help prevent spoofing but don't replace signature verification
- Email metadata (sender, recipient, timestamps) is visible to mail servers
- Consider using dedicated email addresses for nodetide traffic

### Resolution

When contacting an identity:
1. Check sigchain for current `distribution_points` (latest SET_DISTRIBUTION or GENESIS)
2. Try each distribution point in order
3. Fall back to other discovery mechanisms if all fail

Distribution points are hints, not authoritative. The identity hash remains the true identifier.

## Verification Rules

1. Walk chain from genesis
2. Track current valid master key
3. Track active device keys (added, not revoked, not expired)
4. Accept messages signed by any currently-valid key
5. `ADD_CLAIM` and `REVOKE_CLAIM` must be signed by the current master key or by a device that was added, not revoked, not expired at the event's time, and holds `manage_claims`. A `claim_id` may be added only once; a revocation must name an existing, not yet revoked claim. A `SET_CLAIM_ORDER` (same signers) lists 1 to 32 distinct claim ids that exist, are not revoked and have the event's `claim_type`. Chains that break these rules are invalid.

## Design Decisions

### Trustee Format

Trustees are identified by their **identity hash only**:

```
recovery_trustees: [
  "7f3a8b...",  // alice's identity hash
  "9c2d1e...",  // bob's identity hash
  ...
]
```

At verification time, resolve each trustee's sigchain to find their valid signing keys. No circular dependency since `SET_RECOVERY` comes after genesis. References remain stable even if trustees rotate their own keys.

### Recovery Payload

Trustees sign a **structured recovery request**, not just the new pubkey:

```
RecoveryRequest = {
  type: "RECOVERY_REQUEST",
  identity: <hash of genesis being recovered>,
  prev: <hash of last known valid event>,
  new_pubkey: <new master key>,
  timestamp: <unix timestamp>
}
```

This prevents:
- **Replay attacks** - `prev` ties signature to specific chain state
- **Ambiguity** - explicitly names which identity is being recovered
- **Stale signatures** - timestamp allows expiration policy (e.g., reject signatures older than 30 days)

### Conflict Resolution

**Detect forks, flag as conflicted, require explicit resolution.**

In a DTN environment, "first-seen" is unreliable since there's no global ordering.

| Step | Action |
|------|--------|
| **Detect** | Two events with same `prev` = fork |
| **Flag** | Mark identity as "CONFLICTED" - treat messages with suspicion |
| **Display** | For consistency, lower event hash shown as "primary" (display only) |
| **Resolve** | Explicit resolution required (see below) |

Resolution mechanisms:
1. `RESOLVE_FORK` event signed by current master key, choosing a branch
2. Social recovery establishes new canonical branch
3. Revocation on one branch that invalidates the other (e.g., revoking key that signed competing branch)

### Sigchain Distribution

**Full chain by default, delta sync when state is known.**

| Scenario | Approach |
|----------|----------|
| First encounter | Send full chain |
| Subsequent sync | "I have through event N, send N+1 onward" |
| Verification | Always verify from genesis |

Rationale:
- Chains are typically short (tens of events for personal identity)
- Full chain is self-contained, works offline, no coordination needed
- Delta sync is optimization, not requirement
- Compression recommended for multi-hop transports (chains compress well)

## Encoding & Algorithms

**Algorithm agility**: Crypto algorithms and hash functions are not hardcoded. Each event specifies its algorithm, allowing future migration.

```
Event = {
  version: 1,
  alg: "ed25519",
  hash_alg: "sha256",
  ...
}
```

**Event encoding**: JSON for human readability. Can be transcoded to compact binary (CBOR, etc.) for transport if needed.

## Key Capabilities

Device keys can have limited permissions:

```
ADD_DEVICE = {
  device_pubkey: <key>,
  capabilities: ["sign_messages", "sign_files"],  // optional, default: all
  expires: <timestamp>
}
```

Possible capabilities:
- `sign_messages` - can sign chat/messages
- `sign_files` - can sign file attestations
- `sign_identity` - can issue attestations about other identities' claims (see Claims and Attestations)
- `manage_claims` - can add and revoke this identity's own claims
- `encrypt` - can receive encrypted content

## Timestamps

Timestamps are self-reported by default. Optionally, events can include external timestamp witness signatures:

```
timestamp: 1735689600,
timestamp_witness: {
  service: "timestamping.example.org",
  sig: <signature over event hash + timestamp>
}
```

## Discovery

Initial sigchain discovery is transport-agnostic:
- DNS TXT records
- Well-known URL (`.well-known/identity.json`)
- QR code exchange
- Out-of-band sharing (email, chat, paper)

## Revocation Priority

Revocation events are **top priority** in sync protocols. Nodes should propagate revocations before other event types.

Rate limiting should be applied to prevent flooding attacks - a node should not accept excessive revocation events from a single source in a short time window.

## Trustee Liveness

Two mechanisms to handle unresponsive trustees:

**1. Proactive Rotation**
- Replace trustees via `SET_RECOVERY` while you have master key access
- Best practice: rotate trustees periodically

**2. Backup Trustee Tiers**

```
SET_RECOVERY = {
  primary_trustees: [A, B, C, D, E],
  primary_threshold: 3,
  backup_trustees: [F, G, H],
  backup_threshold: 2,
  backup_activates_after: 90 days  // of primary non-response
}
```

If primary trustees fail to respond within timeout, backup tier becomes eligible.

**Minimum trustees**: Configurable, recommend minimum of 3 for primary tier.

## Identity Types

### Pseudonymous

Identities with no real-world binding are allowed. The trust model handles this naturally - nobody will have issued an attestation for a `legal_name` claim of that identity.

### Ephemeral

Short-lived identities explicitly marked:

```
GENESIS = {
  pubkey: <key>,
  ephemeral: true,
  ownership_proof: <signature linking to a persistent identity>  // optional
}
```

Ephemeral identities can optionally prove ownership by a persistent identity (useful for burner accounts that may need later attribution).

### Organizational

Org identities are marked and managed internally by personal identities:

```
GENESIS = {
  pubkey: <key>,
  identity_type: "organization",
  name: "Acme Corp"
}

ADD_ADMIN = {
  admin_identity: <personal identity hash>,
  role: "admin" | "member",
  capabilities: ["add_device", "sign_messages"],
  prev: <hash>,
  sig: <signed by current admin>
}
```

Org actions require signatures from authorized personal identities.

## Trust Model

Scope: Identity verification and trust delegation only. Content trust is out of scope for this system.

### Claims and Attestations

An identity can make **claims** about itself (an email address, a phone number, a legal name). A third party can then issue an **attestation** that it verified a claim. Whether to believe an attestation is entirely up to the party relying on it.

This replaces the earlier `IdentityAssertion`. Strong identification is voluntary: an identity that makes no claims is simply pseudonymous, and a claim is only ever revealed by its holder.

#### Claim

A claim has two parts. Only the first goes on the sigchain.

```
ADD_CLAIM = {                      # sigchain event; master or device with manage_claims
  claim_id: <128 random bits, base64url>,
  claim_type: "email" | "phone" | "legal_name" | "birthdate" | "age_over_18" | "x-<vendor>:<name>",
  commitment: hex(hash("nodetide-claim-v1\0" || claim_id || 0 || claim_type || 0 || salt || 0 || canonical(value))),
  expires: <unix, optional>,
  prev: <hash>, sig: ...
}

REVOKE_CLAIM = { claim_id, reason, prev, sig }

SET_CLAIM_ORDER = {                # sigchain event; master or device with manage_claims
  claim_type: "email", order: [<claim id>, ...],   # first = the holder's default
  prev: <hash>, sig: ...
}

ClaimDocument = {                  # kept by the holder; NOT on the chain
  identity: <identity hash>,
  claim_id, claim_type,
  value: <normalized value>,
  salt: <16 random bytes, hex>
}
```

- **Why a commitment:** a sigchain is public and append-only, so a name or phone number written into it could never be erased. The chain records only that the holder made a claim of some type, and lets the holder revoke it.
- **The salt is mandatory.** Phone numbers and common names are easy to guess; without a random salt the commitment could be reversed by trying candidates.
- **Disclosure:** whoever holds a `ClaimDocument` can recompute the commitment and compare it to the chain. The holder decides who receives it: one verifier, one relying party, or everyone (a *public claim*, e.g. published through a node). Nothing obliges a holder to publish.
- **What stays visible:** that a claim of a given type exists, when it was made, and whether it was revoked or expired.

Normalized values (so that equal values give equal commitments):

| Type | Value |
|------|-------|
| `email` | string `local@domain`, domain lowercased and IDNA-encoded, local part unchanged, surrounding whitespace removed |
| `phone` | E.164 string, e.g. `"+359881234567"` |
| `legal_name` | `{"given_name": "...", "family_name": "..."}`, Unicode NFC, original casing |
| `birthdate` | ISO date `"1990-04-23"`, a real date between 1880 and today |
| `age_over_18` | the boolean `true` (a claim that is not true is simply not made). Lets a holder prove adulthood without a birth date |

Strings are Unicode NFC. Personal identification numbers (national ID, tax ID) are deliberately not a claim type and MUST NOT be copied into claims or attestations. Each attribute is its own claim, so a holder reveals (and has attested) exactly the ones it chooses.

#### Attestation

```
Attestation = {
  type: "ATTESTATION", version: 1,
  subject: <identity hash>,
  claim_id, claim_type, commitment,        # exactly as in the holder's ADD_CLAIM
  method: "email_code" | "eidas_qes" | "manual" | "x-...",
  assurance: "low" | "substantial" | "high",
  issued_at: <unix>, expires_at: <unix>,
  chain_head: <hash of the holder's newest sigchain event the issuer saw>,
  issuer: <identity hash>,                 # absent for self-contained proofs, see below
  signed_by: <issuer device pubkey, hex>,  # absent for self-contained proofs
  evidence: { ... },                       # method specific, never personal data
  proof: { ... },                          # self-contained proofs only
  sig: <issuer device key over "nodetide-attest-v1\0" || canonical(body without sig)>
}
id = hash(canonical(attestation))
```

- **Issuer:** a Nodetide identity (typically an organization identity). Its signing key must be an active device holding `sign_identity`; the master key MUST NOT sign attestations. An attestation says nothing about the claim's *value* beyond what the issuer verified for that commitment, so a relying party still needs the `ClaimDocument` to learn the value.
- **Assurance** follows the eIDAS levels: `low` (control of a channel, such as an inbox), `substantial`, `high` (qualified electronic signature, or an in-person document check).
- **`chain_head`** ties the attestation to a moment in the holder's key history (see Evaluation).
- **Revocation:** `AttestationRevocation = { attestation_id, issuer, signed_by, reason, issued_at, sig }`, signed by an active `sign_identity` device of the issuer under domain `"nodetide-attest-revoke-v1\0"`. Both objects travel as bundles (`attestation`, `attestation_revocation`); revocations get the same priority as other revocations. Attestations expire; issuers SHOULD use at most one year. An attestation signed by a device that is later revoked stops being valid, and a revocation may arrive before the attestation it revokes.

Attestations carry no personal data and are published freely. A node holding a claim's attestations never learns the claim's value unless the holder publishes the document.

##### Self-contained proofs

An authority that is not a Nodetide identity (a government eID scheme, for instance) cannot sign an `Attestation`. Instead the holder obtains a signature from the authority's own scheme over a fixed statement, and the attestation carries it as `proof`. There is then no `issuer`, `signed_by` or `sig`: the proof is the signature, and the relying party validates it against trust anchors it chooses.

**A proof embeds the signer's certificate, which carries personal identifiers (for qualified certificates, typically a national ID number). Attestations with a proof therefore MUST NOT be published, gossiped or stored by nodes.** The holder gives one directly to a relying party, which verifies it (a node can do this statelessly) and discards it.

The statement is plain text so a signing application can show it to the person signing:

```
NODETIDE CLAIM STATEMENT v1
Identity: <identity hash>
Claim: <claim_id>
Type: <claim_type>
Commitment: <commitment>
Chain head: <hash>
Signed on: <ISO 8601 UTC, e.g. 2026-10-25T12:00:00Z>
Valid until: <same format>
By signing I confirm that I control the Nodetide identity above and that
this claim's value is mine.
```

The statement is signed exactly as written (UTF-8, LF line endings, no trailing newline), and a verifier accepts only this canonical form. Binding it to the identity hash, the commitment and the chain head is what prevents replay: an ordinary "this person authenticated" token proves nothing about *which* Nodetide identity is theirs.

#### Verification methods

**`email_code`** (assurance `low`). An independent verification service (never the relying party or node that will rely on it) checks that the holder controls an inbox. The service has its own issuer identity; relying parties pin the identity hashes they accept.

1. The holder sends the verifier the `ClaimDocument` and an `AuthAssertion` bound to the verifier's origin (proof that the request comes from a key of the identity; this also stops anyone using the verifier to send mail to strangers). The assertion's signed `claims` MUST be `{"purpose": "claim_verification", "claim_id": "<the claim>"}`, so the holder's consent covers exactly this claim.
2. The verifier checks the claim exists on the holder's chain, is not revoked or expired, and matches the commitment. It emails a single-use code (valid 15 minutes) to the address, with rate limits per address, identity and client.
3. The holder returns the code (8 characters, single use, five attempts). The verifier issues the attestation. `evidence` is empty; the address is not repeated.

The verifier learns the address and the salt for that one claim, which is inherent to verifying it.

**`eidas_qes`** (assurance up to `high`). The holder signs the statement above with an electronic signature made with a qualified certificate (detached CAdES, `proof = {format: "cades-detached", statement, signature}` with the signature as base64 DER). The relying party validates that:

1. the signature is cryptographically valid and covers the exact statement text; the signer certificate is the one the signature names (ESS signing-certificate or signing-certificate-v2); RSA keys are at least 2048 bits and digests are SHA-2;
2. the statement's identity, claim, commitment and chain head match the attestation; `issued_at` equals the statement's *Signed on*; `expires_at` is not later than the statement's *Valid until* or the certificate's expiry; a signing-time attribute, if present, agrees with *Signed on*;
3. the signer certificate is a certificate for signing documents (key usage content commitment), and its qualified-certificate statements give the assurance: `high` for a qualified certificate on a qualified signature creation device, `substantial` for a qualified one without, otherwise `low`. The attestation's `assurance` MUST NOT exceed it;
4. the certificate chains to a trust anchor the relying party has chosen (for qualified signatures, the CA certificates of qualified trust service providers from the EU trusted lists) and is **currently** valid and not revoked.
5. for `legal_name`, the disclosed value matches the certificate's given and family names exactly, or after transliteration of Cyrillic to Latin by the Bulgarian Streamlined System.

**`eidas_notary`** (assurance up to `high`; `legal_name`, `birthdate`, `age_over_18`). The way to use a government eID signature **without exposing the certificate, and with the holder choosing which attributes are attested**. An independent verification service acts as a notary: the only party that ever sees the certificate.

1. The holder builds a *notary statement* (`NODETIDE NOTARY STATEMENT v1`): human readable, canonical text naming the identity, the **notary's identity hash**, a chain head, a validity window and one `Claim: <id> <type> <commitment>` line per claim to attest (at most five, only the types above). Signing it with the eID card (detached CAdES) is the holder's request: it asks that notary, for exactly these claims, and states that the certificate may be read for that purpose only and must not be kept.
2. The holder sends the statement, the signature and the claim documents to the notary over its own origin, with an `AuthAssertion` for the notary whose signed claims are `{"purpose": "eid_attestation", "statement_sha256": <hash of the statement text>}` (proof that a key of the identity asks for exactly this statement). The signature, which embeds the certificate and so the national ID number, travels to this one party and is never given to a relying party.
3. The notary checks that the statement names it, that the identity and chain head are the holder's, that it is recent (days, not weeks), and that the signature covers the exact text. It validates the signer certificate as for `eidas_qes` (key usage, QC statements, a chain to its own trust anchors, current revocation status).
4. For each listed claim it compares the disclosed value with the certificate: `legal_name` as in `eidas_qes`; `birthdate` against the date of birth the certificate states (the `dateOfBirth` subject attribute, or the birth date encoded in a Bulgarian `PNOBG-` personal number, checksum verified); `age_over_18` against the same date and today. It refuses on any mismatch; a certificate that states no birth date cannot attest one.
5. It issues one ordinary `Attestation` per listed claim (method `eidas_notary`, assurance from the certificate, `evidence = {"source": "eidas_qes", "qscd": true|false}`, a lifetime of at most 90 days and never beyond the certificate). **The attestations contain no certificate, no ID number and nothing about claims that were not listed;** they can be published and shown like any other. The notary does not store or log the certificate.

The price is trust in the notary: a relying party accepting `eidas_notary` attestations trusts the notary's identity (pinned by hash, per claim type, like any issuer) instead of checking the eID chain itself. Accepting the raw `eidas_qes` proof remains possible but shows the certificate to the verifier, so it is not the default.

Point 4 of `eidas_qes` makes a proof-based attestation valid only while the certificate is: it is re-checked every time, and revocation fetching happens only for certificates that already chain to a configured anchor, never from URLs named by an unknown certificate. Proof attestations SHOULD be short-lived (days to weeks) because the proof carries no trusted timestamp. The certificate's personal identifier is not copied anywhere.

#### Evaluating a claim

A relying party holds a policy such as "accept `legal_name` when attested by one of these issuers or by an eIDAS QES, assurance `high`, not older than a year". For a presented `ClaimDocument` and attestation it:

1. finds `ADD_CLAIM` for `claim_id` on the (verified) sigchain; rejects if revoked or expired;
2. recomputes the commitment from the document and compares;
3. validates the attestation: signature and issuer key state for issued attestations, the full proof for self-contained ones; rejects if expired or revoked;
4. checks that the issuer or authority is acceptable under its policy (explicit list, trust anchors, or a trust delegation path, below) and the assurance is high enough;
5. optionally rejects the attestation if the holder's chain contains a `SOCIAL_RECOVERY` after `chain_head`: the people controlling the identity may have changed, so the holder is asked to verify again.

The result is a *verified claim*: type, value, issuer or authority, assurance and age. The same attestation can satisfy one relying party and be ignored by another.

If two acceptable attestations for the same identity and claim type disclose different values, the claim is **contested** and both are shown; the relying party decides.

### Trust Delegation

How much you trust another identity to issue attestations:

```
TrustDelegation = {
  subject: <identity hash>,
  weight: 0.0 to 1.0,
  scope: ["email", "legal_name"],    # optional claim types; absent = all
  depth_limit: <int, optional>,
  timestamp: <unix>
}
```

Weight 0.0 = ignore their attestations. Weight 1.0 = fully trust their judgment. A delegation to an issuer is how a relying party says "I trust this organization to verify legal names".

### Transitive Trust Calculation

```
Path trust = my_delegation(A) × A's_delegation(B) × ... × delegation(issuer)
Multiple paths = max(path1, path2, ...)
Only delegations whose scope includes the claim type count.
Depth limit = a delegation's depth_limit caps how many further delegations may be followed beyond its delegate
```

Example:
- I trust Alice at 0.6, Alice trusts Bob at 0.9 → path trust = 0.54
- I trust Carol at 0.8, Carol trusts Bob at 0.7 → path trust = 0.56
- Result: max(0.54, 0.56) = 0.56

How much an attestation is worth is then `path trust to its issuer`, combined with a local mapping from assurance level to a factor (a relying party's choice, not part of the protocol).

### Migration from IdentityAssertion

`IdentityAssertion` (a third party's opinion, with a confidence from −1 to +1, about who an identity is) is withdrawn. Its use cases move to claims: the holder states a name, someone verifies it. What has no counterpart yet is the *negative* assertion ("this is not that person"); a separate `Dispute` object may fill that role later. Implementations remove it: nodes no longer accept, store, serve or use assertions in trust calculation.

### Several claims of one type

An identity may hold several claims of the same type (two emails, a work and a private phone), each with its own attestations. Nothing merges them:

- **The holder chooses, per sign-in.** A relying party asks for a *type* (a scope); the holder presents **at most one** claim of each type, picking it on the approval screen, or none. Wallets MUST NOT present two claims of one type in a single sign-in; a bridge keeps one value per type (the highest assurance, the first presented on a tie).
- **A default.** `SET_CLAIM_ORDER` records the holder's preference for one type as an ordered list of claim ids. The newest event for a type wins. The *effective order* is that list minus claims that have since been revoked or expired, followed by the type's active claims it does not list, in the order they were made. The first claim in the effective order that has a usable attestation is what a wallet preselects. A holder can have different phones or emails preferred on different devices only by not using the event; the event exists so the choice follows the identity to every device and survives recovery.
- **What it reveals.** Only claim ids, which the `ADD_CLAIM` events already show. It is a preference for wallets, not a statement relying parties may rely on; they never need it, since they receive exactly what the holder chose to present.

### Privacy

- Claim values never appear on a sigchain; only salted commitments do.
- A claim's type and existence are visible. Holders who want to hide even that should keep claims off their identity and present them elsewhere.
- Presenting the same claim to several parties lets them link the identity across services. Unlinkable presentation is out of scope.
- Verifiers and relying parties see only the claims a holder chooses to disclose to them.

### Planned: credentials with built-in selective disclosure

Not implemented, and not testable yet. Two ways to prove "a government vouches for this attribute" without any party seeing an identifier:

- **EU Digital Identity Wallet credentials (PID).** Member states must offer wallets; the Personal Identification Data credential is issued by the state and presented with selective disclosure (SD-JWT VC or ISO mdoc, over OpenID4VP), so the holder reveals only name, birth date or "age over 18" and never the personal number. Support would be a further verification method (and a presentation path in the bridge) whose trust anchor is the issuing state's key, with no notary needed. Timing depends on each country's wallet; Bulgaria's is unknown.
- **Zero-knowledge proofs over a qualified signature.** The holder proves "a valid qualified signature from a certificate chaining to a trusted anchor covers this statement and the certificate states this name or birth date" without revealing the certificate, optionally with a per-context nullifier derived from the ID number for uniqueness. Feasible in principle (circuits for RSA/ECDSA verification and X.509 parsing); heavy to prove on a phone, so a research item.

### Open points

- Trusted-list handling: the reference deployment keeps a published list of links to the CAs' own certificate downloads, each with a pinned SHA-256 fingerprint, and cross-checks every fetch against the member state's trusted list (a service of type QC with status granted). The trusted list's XML signature is not verified, and automatic refresh of the list of trusted lists is not specified.
- Trusted timestamps (CAdES-T) are not required or checked, hence the short lifetimes above.
- Transliteration rules beyond the Bulgarian Streamlined System.
- Other claim types are namespaced `x-<vendor>:<name>` and have no verification methods yet.
- A notary can be a single point of trust and of exposure for the certificate; accepting attestations from several independent notaries is possible but nothing coordinates them.
- Birth date extraction is defined for Bulgarian `PNOBG-` numbers and the `dateOfBirth` attribute only.

## Transport Layer

Hybrid approach: compatible with Bundle Protocol (RFC 9171) where useful, extended/simplified as needed.

Reference implementations: [dtn7-go](https://github.com/dtn7/dtn7-go), [ION-DTN](https://sourceforge.net/projects/ion-dtn/)

### Addressing

Identity-first with optional routing hints:

```
Destination: 7f3a8b... (identity hash)
Hints: [node://abc123, node://def456]  // optional
```

Identity is the address. Hints help routing but aren't authoritative.

### Bundle Format

Single bundle type with in-band type field:

```
Bundle = {
  version: 1,
  type: "revocation" | "sigchain" | "message" | "content_announce" | "ack",
  sender: <identity hash>,
  recipient: <identity hash or "*" for broadcast>,
  ttl: <seconds>,
  created: <timestamp>,
  hints: [<node>, ...],
  payload: <type-specific content>,
  sig: <signed by sender>
}
```

Relays read `type` for priority handling (revocations first).

### Convergence Layer Adapters

Pluggable transport modules. Each CLA handles discovery, connection, and data transfer for its medium.

#### Internet/WAN

**TCP Direct**
| Aspect | Details |
|--------|---------|
| Discovery | DNS SRV/TXT, well-known URLs, static config |
| Connection | Standard TCP/IP |
| Bandwidth | High |
| Latency | Low |
| Use | Primary transport when online |

**WebSocket**
| Aspect | Details |
|--------|---------|
| Discovery | Same as TCP |
| Connection | HTTP upgrade to WS |
| Bandwidth | High |
| Use | Browser clients, firewall traversal |

**QUIC/HTTP3**
| Aspect | Details |
|--------|---------|
| Discovery | Same as TCP |
| Connection | UDP-based, built-in encryption |
| Bandwidth | High |
| Use | Mobile (handles network changes), modern infrastructure |

#### Local Network

**mDNS/DNS-SD**
| Aspect | Details |
|--------|---------|
| Discovery | Multicast DNS broadcast |
| Connection | TCP on local IP |
| Range | LAN only |
| Use | Home/office, same WiFi |

**WiFi Direct**
| Aspect | Details |
|--------|---------|
| Discovery | WiFi Direct service discovery |
| Connection | Peer-to-peer WiFi (no router) |
| Range | ~200m |
| Use | Direct device-to-device |

#### Short Range

**Bluetooth Classic**
| Aspect | Details |
|--------|---------|
| Discovery | Bluetooth inquiry |
| Range | ~10-100m |
| Bandwidth | ~2 Mbps |
| Use | Device pairing, small transfers |

**BLE (Bluetooth Low Energy)**
| Aspect | Details |
|--------|---------|
| Discovery | BLE advertisement with service UUID |
| Range | ~10-50m |
| Bandwidth | ~125 Kbps |
| Power | Very low |
| Use | Background sync, beacons, mobile |

**NFC**
| Aspect | Details |
|--------|---------|
| Discovery | Tap |
| Range | ~4cm |
| Bandwidth | ~400 Kbps |
| Use | Initial pairing, key exchange, small payloads |

#### Mesh/Radio

**LoRa (raw)**
| Aspect | Details |
|--------|---------|
| Discovery | Periodic beacon |
| Range | 2-15km (line of sight) |
| Bandwidth | 0.3-50 Kbps |
| Power | Low |
| Use | Rural, disaster scenarios |

**Meshtastic**
| Aspect | Details |
|--------|---------|
| Discovery | Mesh node announcement |
| Range | Multi-hop extends coverage |
| Bandwidth | Low |
| Features | Built-in mesh routing, encrypted |
| Use | Off-grid communication |

**Ham Radio (Packet)**
| Aspect | Details |
|--------|---------|
| Discovery | Manual/frequency scanning |
| Range | Varies (HF can go global) |
| Bandwidth | Very low |
| Requirements | License required |
| Use | Emergency, remote areas |

**WiFi Mesh (802.11s)**
| Aspect | Details |
|--------|---------|
| Discovery | Mesh beacons |
| Range | Extended via hops |
| Bandwidth | High |
| Use | Community networks, events |

#### High Latency

**Email (SMTP)**
| Aspect | Details |
|--------|---------|
| Discovery | Email address in distribution_points |
| Connection | Standard SMTP/IMAP |
| Latency | Minutes to hours |
| Bandwidth | Moderate (~25MB per message) |
| Coverage | Ubiquitous |
| Use | Async communication, fallback transport, notifications |

**Sneakernet**
| Aspect | Details |
|--------|---------|
| Discovery | Manual |
| Medium | USB drive, SD card, hard drive |
| Bandwidth | Very high (TB per trip) |
| Latency | Hours/days |
| Use | Bulk transfer, air-gapped systems |

**Satellite (Store-forward)**
| Aspect | Details |
|--------|---------|
| Discovery | Service-specific |
| Coverage | Global (Iridium, Starlink, etc.) |
| Latency | Variable |
| Use | Remote areas, maritime |

**SMS/MMS**
| Aspect | Details |
|--------|---------|
| Discovery | Phone number mapping |
| Coverage | Ubiquitous |
| Bandwidth | Very low |
| Use | Notifications, small payloads, bootstrap |

#### Exotic/Experimental

**QR Codes**
| Aspect | Details |
|--------|---------|
| Capacity | ~3KB |
| Use | Identity exchange, small payloads, offline bootstrap |

**Audio/Ultrasonic**
| Aspect | Details |
|--------|---------|
| Range | Room-scale |
| Bandwidth | Very low |
| Use | Pairing, presence detection |

**Steganographic**
| Aspect | Details |
|--------|---------|
| Medium | Images/posts on existing platforms |
| Bandwidth | Very low |
| Use | Censorship resistance |

### Relay Model

**Open relay**: Anyone can offer to relay for any identity. No authorization required.

```
RelayAnnounce = {
  node: <node identity>,
  type: "public" | "identity-specific",
  serves: ["*"] or [<identity>, ...],
  retention: 7 days,
  sig: <signed by node>
}
```

**Relay self-protection**: Relays enforce their own policies:

```
RelayPolicy = {
  rate_limit: 100 messages/hour per sender,
  max_message_size: 64KB,
  retention: 7 days,
  priority_rules: ["revocation > sigchain > messages"],
  blocked_senders: [<identity>, ...]
}
```

**Unreliable relay warnings**: Part of trust model:

```
RelayWarning = {
  relay_node: <node identity>,
  issue: "drops_messages" | "logs_metadata" | "selective_delivery" | "spam",
  confidence: 0.0-1.0,
  evidence: "...",
  timestamp: <unix>,
  sig: <signed by reporter>
}
```

### Large Content

Pull model for content exceeding size threshold (~64KB default):

```
ContentAnnounce = {
  content_hash: <hash>,
  size: 15000000,
  mime_type: "application/zip",
  chunks: [<hash1>, <hash2>, ...],
  available_from: [<node>, ...],
  expires: <timestamp>,
  sig: <signed by sender>
}
```

Relays and recipients fetch on demand based on interest and bandwidth.

### TTL and Retention

- Sender requests TTL in bundle
- Relay may shorten (limited storage)
- Relay may keep longer (not enforceable)
- TTL is hint, not guarantee
- Sensitive content must rely on encryption, not TTL

### Routing

**Sender decides strategy**: Protocol doesn't mandate routing approach.

Options available to sender:
- Direct delivery (if path known)
- Single relay
- Multiple relays (spray)
- Broadcast

### Delivery Confirmation

Relay pickup ≠ delivered. Delivery requires acknowledgment from recipient:

```
DeliveryAck = {
  message_id: <hash>,
  recipient: <identity>,
  received_at: <timestamp>,
  sig: <signed by recipient device>
}
```

Ack is itself a bundle that travels back through the network.

### Transport Security

None at transport layer:
- End-to-end encryption at message layer (when needed)
- Signatures for authenticity
- Transport is public infrastructure

## Messaging Layer

Privacy comes from encryption, not path. All messages travel over public transport.

| Type | Encryption | Distribution |
|------|------------|--------------|
| Private | Encrypted to recipient | Any path |
| Group | Encrypted to group members | Any path |
| Public | Signed only | Broadcast/open |

### Private Messages

Encrypted to recipient's current device key(s) from their sigchain:

```
PrivateMessage = {
  type: "private",
  recipient: <identity hash>,
  encrypted_to: [<device_key_1>, ...],
  ciphertext: <encrypted payload>,
  reply_to: <message hash>,  // optional
  request_receipt: "none" | "delivery" | "read",  // optional
  request_transit_report: true,  // optional
  ephemeral_key: <key>,  // optional, for forward secrecy
  sig: <signed by sender>
}
```

Multi-device: encrypt to all recipient's active device keys.

### Group Messages

Sender chooses encryption mode based on needs:

```
GroupMessage = {
  type: "group",
  group_id: <hash>,
  encryption_mode: "per_member" | "shared_key" | "sender_key",
  ciphertext: <encrypted payload>,
  reply_to: <message hash>,  // optional
  sig: <signed by sender>
}
```

| Mode | Description | Best for |
|------|-------------|----------|
| `per_member` | Encrypt symmetric key to each member | Small groups, one-off messages |
| `shared_key` | Group shares symmetric key, rotated on membership change | Stable groups, high traffic |
| `sender_key` | Each member has own sender key for group | Large groups, forward secrecy |

Recipients must support all modes.

### Group Management

Groups have their own append-only event log (mini-sigchain):

```
GroupDefinition = {
  group_id: <hash of this event>,
  name: "Project X",
  created_by: <identity>,
  membership_policy: "admin_only" | "member_invite" | "open",
  encryption_mode: "per_member" | "shared_key" | "sender_key",
  sig: <signed by creator>
}

GroupEvent = {
  type: "add_member" | "remove_member" | "rotate_key" | "change_admin",
  group_id: <hash>,
  subject: <identity>,
  prev: <hash>,
  sig: <signed by admin>
}
```

### Public Messages

Signed but not encrypted. Anyone can read:

```
PublicMessage = {
  type: "public",
  sender: <identity hash>,
  recipient: "*",
  content: <payload>,
  reply_to: <message hash>,  // optional
  sig: <signed by sender>
}
```

### Forward Secrecy

Optional. Sender includes ephemeral key for forward secrecy when needed:

| Mode | Use case |
|------|----------|
| Static keys | Default, simple, works with DTN delays |
| Ephemeral keys | Opt-in when forward secrecy matters |

Ephemeral key exchange requires overhead, may not complete in high-latency scenarios.

### Receipts

Optional, sender-requested, recipient may ignore:

```
DeliveryAck = {
  message_id: <hash>,
  recipient: <identity>,
  received_at: <timestamp>,
  sig: <signed by recipient>
}

ReadReceipt = {
  message_id: <hash>,
  recipient: <identity>,
  read_at: <timestamp>,
  sig: <signed by recipient>
}
```

### Transit Reports

For debugging delivery issues. Optional, may be ignored:

```
TransitReport = {
  message_id: <hash>,
  hops: [
    {node: <identity>, received: <timestamp>, forwarded: <timestamp>},
    ...
  ],
  sig: <signed by reporter>
}
```

### Threading

Simple parent reference. Clients reconstruct threads locally:

```
reply_to: <message hash>  // optional
```

## Content Layer

MIME-style content containers. Leverage existing standards and tooling.

### Content Structure

```
Content = {
  content_type: "text/plain",  // any MIME type
  content_encoding: "utf-8" | "base64",
  content_disposition: "inline" | "attachment",
  filename: "document.pdf",  // optional
  body: <content>
}
```

Any MIME type allowed. Clients decide what to render/handle.

### Multipart Content

```
MultipartContent = {
  content_type: "multipart/mixed" | "multipart/alternative" | "multipart/related",
  parts: [
    {content_type: "text/plain", body: "..."},
    {content_type: "text/html", body: "..."},
    {content_type: "application/pdf", filename: "doc.pdf", body: <base64>}
  ]
}
```

| Multipart type | Use |
|----------------|-----|
| `mixed` | Message with attachments |
| `alternative` | Same content, different formats (plain + HTML) |
| `related` | HTML with inline images |

### Content Addressing

All content is hash-addressable:

```
content_hash = hash(canonical(content))
```

Used for:
- Deduplication
- Integrity verification
- References (reply_to, edits, large content)

### Large Content (Chunked)

Content exceeding size threshold is split into manifest + chunks:

```
ContentManifest = {
  content_hash: <hash of full content>,
  content_type: "application/zip",
  total_size: 50000000,
  chunk_size: 65536,
  chunks: [
    {index: 0, hash: <hash>, size: 65536},
    {index: 1, hash: <hash>, size: 65536},
    ...
  ],
  sig: <signed by sender>
}

ContentChunk = {
  manifest_hash: <hash of manifest>,
  index: 0,
  data: <bytes>
}
```

**Verification:**
1. Receive manifest, verify sender signature
2. Fetch chunks independently (any order, any source)
3. Verify each chunk hash against manifest
4. Reassemble

**Benefits:**
- Partial/resumable fetch
- Multi-source fetch (different relays)
- Single signature covers all chunks
- Configurable chunk size

| Size | Strategy |
|------|----------|
| < threshold | Inline in message |
| ≥ threshold | Manifest + chunks |

Threshold configurable per node (default ~64KB).

### Edits and Versions

Content is immutable. Edits create new content referencing original:

```
Content = {
  ...
  edit_of: <original content hash>,
  version: 2,
  ...
}
```

Clients display latest version, may show edit history.

### Deletion Requests

Polite request, not enforceable:

```
DeleteRequest = {
  content_hash: <hash>,
  reason: "...",
  sig: <signed by author>
}
```

Relays and recipients may honor or ignore. Content may persist.

### Content Trust

Separate concern from identity trust. To be designed separately.

Potential dimensions:
- Authenticity (who created it)
- Quality/accuracy
- Safety (malicious content)

## Authentication (SSO)

Lets an identity prove control of its keys to a third-party service (the **relying party**, RP) without a shared secret or a central identity provider. The sigchain is the credential store; a device key signature is the credential.

### The `authenticate` Capability

A new device capability, separate from `sign_messages` and `sign_files`:

```
ADD_DEVICE = {
  device_pubkey: <key>,
  capabilities: ["authenticate", "sign_messages"],
  ...
}
```

- A key may produce an `AuthAssertion` only if it holds `authenticate`.
- The master key MUST NOT sign `AuthAssertion`s. Logins use device keys so the master stays out of daily use.
- If `capabilities` is omitted (default: all), `authenticate` is included, but clients SHOULD grant it explicitly.

### Auth Request

The RP generates a challenge and delivers it by any means (redirect, QR code, deep link, BLE, NFC):

```
AuthRequest = {
  type: "AUTH_REQUEST",
  aud: "https://app.example.com",   // RP origin; REQUIRED
  nonce: <128+ random bits, base64url>,
  issued_at: <unix>,
  expires_at: <unix>,               // RECOMMENDED lifetime <= 5 min
  callback: "https://app.example.com/auth/callback",  // optional
  claims: ["name"],                 // optional, see Claims
}
```

### Auth Assertion

The signer shows the user `aud` and any requested `claims`, and asks for consent. If approved, it signs:

```
AuthAssertion = {
  type: "AUTH_ASSERTION",
  identity: <identity hash>,
  device: <device pubkey>,
  aud: <copied from request>,
  nonce: <copied from request>,
  iat: <unix>,
  exp: <unix, <= request.expires_at>,
  chain_head: <hash of newest sigchain event the signer knows>,
  sig: <signature by device key over canonical(assertion without sig)>
}
```

The signature input is prefixed with the domain-separation string `"nodetide-auth-v1\0"` so an `AuthAssertion` signature can never be valid as a message, file or trust-assertion signature.

`chain_head` lets the RP detect stale state: if the RP's copy of the sigchain does not contain `chain_head`, it MUST fetch the newer chain before deciding. This closes most of the revocation-latency gap in DTN settings.

### RP Verification

1. Check `aud` equals the RP's own origin, `nonce` matches an outstanding request that has not been used, and `iat <= now <= exp` (allow small clock skew).
2. Obtain the sigchain for `identity` (distribution points, `.well-known/identity.json`, or supplied alongside the assertion) and verify it from genesis.
3. If `chain_head` is not in the chain, fetch a newer chain and re-verify.
4. Check `device` is currently active in the chain the RP holds (added at or before `iat`, not revoked, not expired), holds `authenticate`, and is not the current master key. A revocation the RP knows about wins even if it happened after `iat`.
5. Verify `sig` with `device`.
6. Mark the nonce used.

The RP learns the stable identity hash, not any real-world name. The hash stays constant across key rotation and recovery, so the RP can use it as a durable account key.

### Presented claims

Optional. Anything beyond the identity hash is either self-asserted by the user (the `claims` object inside an `AuthAssertion`) or backed by a claim and attestation (see Claims and Attestations).

| Claim | Source |
|-------|--------|
| `name` | Genesis `name` (self-asserted), or a `legal_name` claim with an attestation the RP accepts |
| `email`, `phone` | A claim document plus an attestation, evaluated by the RP |

Values in the `claims` object of an assertion are signed but are only as strong as their source. RPs MUST NOT treat self-asserted values as verified.

### Transport Bindings

**Native (challenge-response).** The RP presents an `AuthRequest`; the client returns an `AuthAssertion`. This is the core protocol and needs no other infrastructure.

**OpenID Connect (self-issued, SIOP v2).** For RPs that speak OIDC, the `AuthAssertion` is wrapped as an `id_token`:

```
header:  { alg: "EdDSA", typ: "JWT", kid: <device pubkey> }
payload: { iss: <identity hash>, sub: <identity hash>, aud, nonce, iat, exp,
           nodetide_chain_head: <chain_head> }
```

- `iss` equals `sub` (self-issued). The RP resolves the sigchain to find the key behind `kid`.
- The token MUST be signed with an asymmetric algorithm (EdDSA). Symmetric algorithms (HS256) MUST NOT be used.
- Standard libraries can validate structure and `aud`/`nonce`/`exp`, but trusting `kid` requires the sigchain check above, so a Nodetide-aware verification step is still needed.

**Bridge IdP (OIDC).** For applications that cannot be changed, a node MAY run a conventional OIDC provider (authorization-code flow with PKCE, RS256 `id_token`s signed with the bridge's own key). Any Nodetide identity can sign in; the bridge needs no prior registration of users. The bridge is a trusted party: it can impersonate any user to RPs that trust it. SAML is out of scope.

- **Audience:** the bridge's issuer URL. Each sign-in attempt carries an `AuthRequest` with `aud = issuer`.
- **Subject:** `sub` is the identity hash, stable across key rotation and recovery.
- **Answering a sign-in:** the sign-in page shows a deep link `nodetide://login?challenge_url=<url>`. The user's Nodetide app fetches the challenge (`AuthRequest` plus display info such as the RP name), shows the RP name and issuer for consent, and POSTs `{assertion, sigchain?, hints?}` to the `respond_url`. The sigchain is optional; it makes sign-in instant for identities the bridge has never seen.
- **Browser binding:** the page that polls for the result holds a secret carried in the URL fragment, so someone who only saw the deep link or QR code cannot collect the authorization code.
- **Verified claims:** applications ask for claims by scope (`profile` → `legal_name`, `email` → `email`, `phone` → `phone`). The user's app presents a claim document and its attestation alongside the assertion; the bridge applies its own rules (accepted issuers or proof types, minimum assurance, maximum age, no social recovery since the attestation) and releases only what passes and was asked for, as `email`/`email_verified`, `name`/`given_name`/`family_name`/`name_verified` and an OpenID Connect for Identity Assurance `verified_claims` block. A presentation that does not satisfy the rules releases nothing; it never fails the sign-in. A name taken from the identity's genesis event is released only as `name` with `name_verified: false`.
- **Unknown or stale identities:** when the bridge has no sigchain for the identity, or the signer's `chain_head` is newer than its copy, it queues a background fetch and tells the user sign-in has *failed for now*. Fetch sources are the `hints` from the app, an optional `login_hint=<identity hash>@<node url>`, the identity's own distribution points once known, and operator-configured seed nodes. Fetches are persisted, retried with backoff, and verified from genesis before use. When the chain arrives and the pending assertion is still valid, the sign-in completes by itself; if the assertion expired meanwhile, the user is asked to approve once more (now instant). A sign-in page that times out returns `error=temporarily_unavailable` to the RP, and the fetch continues, so a later attempt succeeds.
- **Fetching untrusted URLs:** hints are attacker-controlled, so the fetcher MUST NOT contact non-public addresses, follow redirects, or read unbounded responses (SSRF).

### Sessions

An RP that accepts an `AuthAssertion` creates its own session. Nodetide nodes MAY issue sessions for their own APIs the same way. Session lifetime is the RP's choice; high-value actions SHOULD require a fresh `AuthAssertion`.

### Security Considerations

- **Phishing and relay:** `aud` binds the assertion to one origin. A phishing site can only obtain assertions for its own origin. Clients MUST display `aud` to the user and MUST NOT show an RP-supplied name instead.
- **Replay:** one-time nonces plus short expiry. RPs MUST track nonces until expiry.
- **Revocation:** `chain_head` plus the active-device check bounds how long a revoked device can keep logging in. RPs with high security needs SHOULD always fetch the current chain.
- **Device compromise:** revoke the device (`REVOKE_DEVICE`). RPs that cached the chain learn of it on next fetch or via revocation propagation.
- **Key reuse:** domain separation prevents cross-protocol signature reuse, but deployments SHOULD use a dedicated device key for `authenticate` where practical.
- **Account recovery at the RP:** because `identity` is stable across `ROTATE_MASTER` and `SOCIAL_RECOVERY`, RPs need no account-recovery flow of their own for key loss.
- **Correlation:** a single identity hash is a global correlator across RPs. Users who need unlinkability SHOULD use a separate (pseudonymous or ephemeral) identity per RP. Pairwise derived identifiers are possible future work.

## Identity Dump Format

Portable backup format for identity with encrypted private keys. Compatible between CLI and web client.

### Structure

```json
{
  "version": 1,
  "format": "nodetide-identity-dump",
  "identity_hash": "<sha256 hash of genesis event>",
  "sigchain": [<array of sigchain events>],
  "encrypted_keys": {
    "v": 1,
    "kdf": "pbkdf2-sha256",
    "kdf_iterations": 100000,
    "cipher": "aes-256-gcm",
    "salt": "<16 bytes hex>",
    "iv": "<12 bytes hex>",
    "ciphertext": "<encrypted keys + GCM tag, hex>"
  }
}
```

### Encryption Details

| Parameter | Value |
|-----------|-------|
| KDF | PBKDF2 with SHA-256 |
| KDF iterations | 100,000 |
| Key length | 256 bits |
| Cipher | AES-256-GCM |
| Salt | 16 random bytes |
| IV/Nonce | 12 random bytes |
| Auth tag | 16 bytes (included in ciphertext) |

### Decrypted Keys Format

The `ciphertext` decrypts to JSON:

```json
{
  "signing_key": "<ed25519 secret key, 64 bytes hex>",
  "encryption_key": "<x25519 secret key, 32 bytes hex>"
}
```

### Usage

**CLI:**
```bash
# Dump (prompts for password)
nodetide identity dump backup.json

# Restore
nodetide identity restore backup.json
```

**Web:**
- Settings → "Dump Identity" (requires unlocked identity)
- Settings → "Restore Identity"

### Security Notes

- Password-based encryption - security depends on password strength
- 100k PBKDF2 iterations provides reasonable protection against brute force
- Random salt prevents rainbow table attacks
- AES-GCM provides authenticated encryption (integrity + confidentiality)
- Store dump files securely - they contain encrypted private keys

## Related Systems

| System | Approach |
|--------|----------|
| **PGP** | Master key + signing/encryption subkeys |
| **Signal** | Identity key + device prekeys |
| **Keybase** | Per-device keys, sigchain for rotation |
| **KERI** | Key Event Receipt Infrastructure - append-only log of key events |
| **DID methods** | Various, some support key rotation via signed updates |
| **Scuttlebutt** | Identity = pubkey hash, append-only feed |
