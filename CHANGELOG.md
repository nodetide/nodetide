# Changelog

Progress notes kept between sessions. Newest first. Each entry says what changed, why, and what is
still open, so a new session can pick up without re-deriving context.

## 2026-11-01 (layout) - claims live in the My Identity tab

- The separate Wallet tab is gone: the identity's claims (add, verify, timeline, renounce, publish), the passkey control and "Organizations you own" are in the **My Identity** tab,
  under the identity info. The sign-in approval screen returns there on Cancel.

## 2026-11-01 (sigchain v2) - a control chain that commits to its content; light verification

Clean slate: v1 chains are not read (the test server's data is dropped). Spec: `sigchain-v2.md`.

### Changed
- **Two tracks per identity** (`core/identity.py`): the *control* chain (genesis, devices, rotation, recovery, owners, `revoke_claim`, new `checkpoint`; linked by
  `prev`) and the *content* track (`add_claim`, `set_claim_order`; `seq`, `prev` = previous content event, `control_ref` = the control event signed under).
  `Sigchain.events` is the control chain (so identity hash, head and device checks are as before); `Sigchain.content` the claims. The identity hash is still the hash
  of the genesis.
- **Commitments**: a control event carries `content: {count, root}` (Merkle root, `core/merkle.py`, RFC 6962 style) over the first `count` content events; every
  control event created while content exists commits all of it. A content event is valid only if its signer was authorized as of `control_ref` and the *next*
  control event commits it, so a revoked key cannot back-date claims.
- **Light verification**: a chain without content (`to_list(light=True)`) verifies as `is_partial`; `attach_content(event, proof)` accepts one content event with its Merkle
  path (`content_proof(seq)`); revocations are control events so a light client sees them all. A half-uploaded chain still has every present event checked.
- **Behind, not wrong**: an object naming a control event the verifier lacks is reported as behind (`unknown_chain_head` for attestations, `behind:` for content, HTTP
  409 `stale_state` with `behind: true` on the node) before anything else; the fetcher already goes to other sources for it.
- Node API: events go to their track (`prev` is checked against that track's head); `GET /identities/{h}/sigchain?light=1`, `GET /identities/{h}/content/{seq}` (event +
  proof); responses carry `content_length`, `commitment`. The explorer shows both tracks (an event page says which). The OIDC bridge accepts a light chain plus
  `claim_event`/`claim_proof` per presentation. `choose_sigchain` merges a newer light copy with the stored content.
- Web client: claims are content events; control events it signs carry the commitment; it publishes a `checkpoint` before a claim is attested; sign-in sends the
  control chain and one Merkle path per shown claim (full chain if a claim is not committed yet).
- Test wallet app (`deploy/test/wallet`) publishes control then content events by track.

### Not done
- Go (`golang/auth`) and Android still speak v1; they agree with v2 only for identities without claims.
- Verifiers (email/phone/eID) still take the full chain; the light path is used at sign-in. Freshness (proving there is nothing newer than a shown head) is open.

## 2026-11-01 (browser wallet) - claims and verification in the browser, no server-side keys

### Added
- **Browser wallet** (`web/js/app.js`, view "Wallet"): add email and phone claims, verify them with a code from the verification service, keep the
  attestations. Claim values, salts, attestations, issuer chains and pending verifications are one blob in localStorage, encrypted with the identity's
  password (PBKDF2 + AES-GCM); the unlocked keys, the password and the decrypted data exist only in memory (`WalletSession`) and are dropped after 15 idle
  minutes or on reload. The backup file now carries the wallet data and a restore brings it back. Commitments, claim normalization and assertions are
  byte-compatible with `core/claims.py` / `core/auth.py` (checked by the verifier recomputing them in the browser test).
- The node serves `/api/web-config` (`NODETIDE_WEB_VERIFIER_URL`, set from `VERIFIER_URL` in the test stack); the verifier answers CORS for its public,
  assertion-authenticated endpoints (`/api/verify/*`, `/api/auth/challenge`, `/api/issuer/request`).
- Test: `python/tests/test_web_wallet_browser.py` (headless Chrome, real verifier on another origin).

### Fixed
- The client's canonical JSON did not escape non-ASCII like Python's `json.dumps`, so a name or label such as "Алекс" gave a signature and identity hash
  the node rejects. The web client's device was also given capabilities that do not exist (`sign`, `decrypt`); it now gets `authenticate` and
  `manage_claims` (an existing web identity is re-authorized the first time it verifies a claim).

- **Sign in with the browser wallet**: the node's sign-in page links to `/signin?link=...` (the node serves the client there); the client previews what the
  site asks, offers one attestation per claim type (best assurance first), signs the assertion with the device key and posts it with the presentations
  and issuer chains. It only signs in to its own node. Tested end to end against the real OIDC bridge (the verified email reaches `userinfo`).
- **No public wallet**: the Caddy route, DNS record (`nt-wallet`) and the node's wallet link are gone; the OIDC page offers the web client. The old
  server-side wallet is the opt-in compose profile `hosted-wallet` (127.0.0.1:4572, ssh tunnel), still used by `smoke.py` and for the eID statement flow.

- **Passkey unlock** (`Passkey` in `web/js/app.js`): "Use a passkey" in the Wallet view makes a WebAuthn credential with the PRF extension and wraps the identity
  password under HKDF(PRF(salt)) (AES-GCM); "Unlock with passkey" in the wallet and sign-in views unwraps it (user verification required). The password stays
  the root secret and the fallback, the wrapped copy lives only in this browser's storage, and removing the passkey deletes it. The RP id is the page's host name
  (a passkey does not follow the site to another domain). Tested with a CDP virtual authenticator (`test_passkey_unlocks_the_wallet`). Not a signing key: the
  protocol's keys are still Ed25519 and the backup file remains the safety net.
  Also in "Create Identity": the Passkey option (it was hard-disabled as "not supported") makes an identity with NO password: a random secret generated in the
  browser, held only wrapped by the passkey (`storageMethod: webauthn`). Forms that ask for the identity password accept an empty field for such an identity
  and the passkey stands in (backup, recovery, organization approval, unlock). Those forms no longer show the "identity password" field at all when a passkey or
  an unlocked wallet can supply it (`protection.needsPassword`); they say who confirms instead.

- A verifier whose owned issuer is not set up yet answers every API call with `503 {error: issuer_not_ready, message}` (CORS-readable) instead of 404, and the
  browser wallet shows "The verification service is not ready yet: <reason>".

- **No operator steps after the approval**: the waiting verifier looks for the organization whose genesis is the one it signed (exact match, our own key's
  signature) and, once the owners' approval reaches the node, adopts it (`issuer_org` table), restarts itself and issues; `ISSUER_ORG` is no longer needed. The
  node trusts the issuer in `NODETIDE_OIDC_ISSUERS_FILE` (the file the verifier publishes) and re-reads it when it changes, so it is not restarted either. The
  approval card fetches the founding request from the verification service by itself.

- "Organizations you own" (Wallet tab) lists the organizations whose current owners include the active identity: name, kind, hash, owners with their share,
  devices.

- **Claims in the browser wallet**: one claim per value (the same address in any case or spacing is refused; the chain holds only salted commitments, so only the
  wallet can notice). **Renounce** any claim, verified or not: a `revoke_claim` event on the chain; the claim is hidden by default (a "Show renounced claims"
  switch lists them), is never offered for a sign-in or verified, and its value can be claimed again. Nothing is forgotten locally: every claim has a **Timeline**
  (claimed on the chain, codes requested here, verified by whom with what assurance, attestation expiry, renounced), the **raw events** behind it (the
  `add_claim`/`revoke_claim` events and the issuer's attestation) and links to the **explorer** for the event and the identity.

- **Attestations reachable in the explorer**: an identity page now has "Attestations about it" and "Attestations it issued" (counts, linking to the filtered
  attestations list), so an issuer such as the verifier's organization has a way in. The list was empty because attestations live in holders' wallets; the
  browser wallet can now **Publish attestation** for a verified claim (POST /api/attestations; public, shows that the claim is attested and by whom, never the
  value) and the claim's timeline records it.

- Explorer: `#/identity/<start of hash>` and `#/event/<start of hash>` resolve to the one match (or list several / say none) instead of "Page not found".

- **Service worker fixed** (`web/sw.js`): it served the app from its cache and refreshed it in the background, so a browser showed the previous version until a
  second reload (and the explorer/wallet changes looked missing). The app is now network first (cache only as the offline fallback), cache name bumped. Test:
  `test_a_new_version_of_the_app_is_used_on_the_next_load` (fails with the old worker).

### Open
- Browser UI for eID statements, legal name, birth date and age claims (only the hosted/local wallet has them); device pairing and claim sync between
  browsers; a content security policy for the web client; `navigator.storage.persist()`.

## 2026-11-01 (owners) - organization identities owned by weighted owner identities

### Added
- **Owners** (`core/identity.py`, section "Organization identities"): an organization genesis may declare `owners` (`[{identity, weight}]`, personal
  identities, 1..16, integer weights) and carries every founding owner's approval. `rotate_master` (recovering the organization's key) and the new
  `set_owners` are then *governed*: `signed_by` is `"owners"`, no signature of their own, only `approvals`; valid when approving weight is MORE than half
  of the declared weight (owners and weights in force before the event). The organization runs itself with its own key: devices, claims, distribution and a plain rotation are ordinary events it signs; its key cannot change the owners or set recovery.
- An approval names the owner's chain state and is checked against the owner's key as of that state, so an owner who rotates or recovers their key keeps
  old organization events valid and needs no organization event (the organization's recovery is the owner's recovery). A node also demands the owner's
  *current* key for a new event (`verify(resolve, check_current=True)`); `POST /api/identities`, `/events` and `/api/verify` pass the node's storage as
  resolver.
- Organizations without owners (every one before this) keep working, governed by their own key.
- Tests: `python/tests/test_org_identity.py`, one node round trip in `test_pairing_api.py`.

- **Social recovery that works** (`core/identity.py`): a `social_recovery` event is signed by the NEW key and needs `primary_threshold` distinct
  trustees from the latest `set_recovery`, each signing (identity, chain head, new keys) with the key they had at a named chain state (a node demands
  their current key). `set_recovery` is checked too: distinct trustees, not yourself, threshold 1..n. The node used to build an unsigned event itself
  and never checked trustee signatures; now `POST .../recovery/{id}/sign` verifies each signature, the status carries the records once the threshold is
  met, and the recovering client signs and submits the event. At most 5 pending recoveries per identity; backup trustees are still not used.
- Web client: "I lost my keys (recover with trustees)" and "Help someone recover" (identities view). The recovering browser makes a new master key,
  shows a recovery code for the trustees, and on completion publishes the recovery, adds a device and keeps the identity (it needs a new backup
  afterwards). The headless-Chrome test covers losing keys twice and a browser identity vouching for a Python one.

- **Owned issuer** (`verifiers/issuer.py`, `ISSUER_OWNED=1`, `ISSUER_OWNERS`): the verifier holds the organization's own key and a signing device (table
  `owned_issuer`) and serves the founding request (the genesis its key signed, naming the owners) at `/api/issuer/request`. The owners approve it in the web
  client (card "Organizations you own"); with `ISSUER_ORG` set the verifier fetches the organization with its owners' chains from `NODETIDE_ISSUER_NODE`,
  verifies it, and authorizes its own signing device with the org key. Until then the service only waits and serves the request. If the owners replace the
  organization's key the verifier stops with a clear reason; it cannot yet adopt the new key (open). `verify_attestation`, `verify_revocation`, `evaluate_claim`, the claims API, the OIDC provider, the identity
  fetcher (which also fetches missing owner chains) and the explorer now pass the node's storage as resolver. The issuer info carries `owner_sigchains`.
- Test stack: `ISSUER_OWNED`, `ISSUER_OWNERS`, `ISSUER_ORG` in `.env` (README "Owned issuer"); default stays the old self-made issuer.

- **Two kinds of owned organization**, chosen in the genesis (`governance`, fixed for life): `self` (default; the org's own key handles devices, owners only
  recover the key and change owners; for automated services such as the verifier, so no owner key is involved in their activity) and `managed` (owners also
  approve `add_device`/`revoke_device`; the org key cannot make them or rotate itself). `ISSUER_GOVERNANCE` picks it for the verifier; the web client can
  authorize a verifier's signing key for a managed organization.

### Open
- Backup trustees and the test wallet app (`deploy/test/wallet`) have no recovery UI yet; recovery restores control of the identity, not claim values.
- Other `verify()` callers (claims, auth, explorer, OIDC, relay, daemon, email verifier) do not pass a resolver yet, so an owned organization fails there
  until they do. Next: trustee-signed `social_recovery` (the check is still a TODO), then the verifier's device key and the signing step in the wallet.

## 2026-11-01 (protection) - one identity on several devices, wallet as a macOS app, and a banner until the identity is recoverable

### Added
- **Pairing** (`python/src/nodetide/api/pairing.py`, `/api/pairing`): a new wallet makes its own device keys and opens a slot on the node named by the
  hash of a 10-character code it shows; the wallet that holds the master key authorizes it (`Identity.authorize_device`, an `add_device` event) and
  leaves the claim values and attestations sealed to the new device's key. The new device checks the chain, its own authorization, the sender and every
  claim commitment before using the answer. Slots live 10 minutes in memory. One-time copy, no sync yet.
- **Wallet without the master key** (devices with `manage_claims` sign claim events), **state encrypted with a Keychain key** (`WALLET_KEY_STORE=keychain`)
  and **`deploy/test/macos-app/`**: the wallet as a PyInstaller menu-bar app (one-time launch link instead of the HTTP password, first-run choice to pair).
- **Protection banner, in the wallet and the web client**, until (1) an encrypted backup exists and (2) social recovery is configured. Backup:
  PBKDF2-SHA256 with 1,000,000 rounds + AES-256-GCM (the working copy of the keys uses 100,000), password of 12+ characters that is not trivially weak,
  read back before it is counted, includes the master key; a wallet backup goes out of date when claims or attestations change. Recovery: at least 3
  trustees that exist on the node, threshold 2..n, published as a `set_recovery` event. Both clients can restore from the backup.
  `crypto.py`: `BACKUP_KDF_ITERATIONS`, `weak_password_reason`, a bound on the cost read from a file.

### Fixed
- **`POST /api/identities` replaced the stored chain whenever a genesis event was posted again**, so anyone holding a (public) genesis event could erase an
  identity's devices, claims and recovery settings on the node. Re-posting a known genesis is now an idempotent 200 that changes nothing (test added).
  The node on the test server has it only after the next deploy.
- The web client's old "dump" held only the device key, with an 8-character minimum and 100,000 rounds; it now opens the new backup dialog.

### Open
- Claims added later on one device do not reach the other (no sync); devices cannot be revoked from the UI; the master key stays on the first wallet.
- The recovery event exists but the flow that *uses* it (collect trustee signatures, `social_recovery`) has no UI yet.
- `tests/test_web_protection_browser.py` drives headless Chrome (needs Chrome and internet) and runs only with `NODETIDE_BROWSER_TESTS=1`.

## 2026-10-26 (trust anchors) - published links with pinned fingerprints instead of certificates in the repo

### Added
- **`deploy/test/trust-anchors.json`**: the published list of links to the CAs' own certificate downloads, each with the SHA-256 it must have.
  **`fetch-anchors.py`** (stdlib only) downloads them into `anchors/` (git-ignored), refuses any mismatch, and cross-checks every run against the
  EU trusted list of the country (`--strict`: stop unless the pinned certificate is a *granted QC* service). The deploy workflow runs it before
  every deploy; `deploy.sh` passes `ANCHORS_REV` so the verifier is recreated when the anchors change. 17 tests.
- First entry: **B-Trust Operational Qualified CA** (BORICA AD), `https://ca.b-trust.org/repository/B-TrustOperationalQCA_DER.crt`, sha256
  `499a9ca8...ba0c`, valid to 2033-05-31. Verified by downloading it from BORICA's repository and finding the same fingerprint in the Bulgarian
  trusted list (`https://crc.bg/files/_en/TSL_BG.xml`, from the EU list of trusted lists) as type QC, status granted.

### Findings
- The Bulgarian list grants the **intermediate** "B-Trust Operational Qualified CA", not the roots (Root Qualified CA, Root CA5 are not services in it).
  So the intermediate is the anchor; the validator accepts that (tested). The older "B-Trust Operational CA QES" (Root CA5 chain) is **withdrawn**
  and expired in 2025: a card issued from that chain would not validate.
- One certificate backs several services in the list (QC, registration, identity proofing); the check accepts it if any is a granted QC.

### Open
- The card was not readable (no token detected) so its issuing CA is unconfirmed; if it chains to the withdrawn CA5 QES the notary will refuse it.
- The trusted list's own XML signature is not verified (pins are what is trusted); automatic LOTL/TL handling stays an open point in the spec.

## 2026-10-26 (choice) - several emails or phones, a default, and a pick on the approve page

### Added
- **`SET_CLAIM_ORDER` sigchain event**: master or a `manage_claims` device lists the claims of one type in preferred order (first = default).
  Rules: 1 to 32 distinct existing, unrevoked claims of that type. `Sigchain.claim_order(type)` gives the effective order (newest event, minus
  revoked/expired claims, then the unlisted ones in the order made); `Identity.set_claim_order(...)`. It reveals only claim ids. Added to the Python
  chain verifier, the **Go chain verifier** (which rejects unknown event types), the explorer's event summary and the session capability map;
  14 Python tests and 2 Go tests. Chose a chain event (like `SET_DISTRIBUTION`'s ordered list) over wallet-local state so the default follows the
  identity across devices and recovery.
- **Wallet**: the approve page shows one radio group per requested claim type (every usable claim in the holder's order, default preselected,
  plus "share none"); the wallet refuses to present two values of one type. Dashboard: rank, "make default", move up/down per claim.
- Spec: "Several claims of one type" (holder chooses per sign-in, at most one per type, default semantics). The bridge is unchanged: it keeps one
  value per type (highest assurance, first on a tie), which is why wallets must send one.
- Smoke test: two verified emails; default, change of default and an explicit pick each reach the application as chosen.

### Open
- Other wallets/apps must adopt the same "one per type, default preselected" behaviour; nothing enforces it beyond the bridge keeping one value.
- No per-application memory yet ("always use my work email for this site"); it would be wallet-local state, not a chain event.

## 2026-10-25 (privacy) - eID notary: attest from a government signature without exposing it

### Added
- **`eidas_notary`**: the verification service validates a CAdES signature from the person's eID card and issues ordinary
  attestations; the certificate (with the personal number) goes to that one party. `POST /api/verify/eid/attest`.
  - **Notary statement** (`eidas/notary_statement.py`): canonical text naming the identity, the notary's identity hash, a chain head,
    a validity window and one `Claim:` line per claim to attest (max 5, `legal_name | birthdate | age_over_18`). The request is bound
    to it (`AuthAssertion` with the statement's sha256), so a leaked file is useless to another notary and the holder decides what is attested.
  - **`EidNotary`** (`verifiers/eid_notary.py`): checks signature, certificate chain (own trust anchors, revocation), freshness, then each
    claim against the certificate; refuses on mismatch; one attestation per listed claim with `evidence {source, qscd}`, no certificate,
    no number. Certificate is never stored or logged (a test checks the log).
  - **New claim types** `birthdate` (ISO date) and `age_over_18` (`true`), so a person can prove adulthood without a birth date. Birth date
    comes from the certificate's `dateOfBirth` attribute or a Bulgarian `PNOBG-` EGN (checksum verified, century by month offset).
- **Bridge**: `NODETIDE_OIDC_NOTARY_ISSUERS` (pin for the eID-derived claims, high assurance); scopes `birthdate` and `age_over_18`, released as
  standard `birthdate` / `age_over_18` plus `verified_claims` entries; `eidas_notary` counts as the `eidas` trust framework.
- **Wallet**: tick the claims to attest, get one statement, upload the signature (sent to the notary, never stored), keep attestations only.
  `nodetide eid sign-file` accepts notary statements and prints what it signs before the PIN prompt.
- **Test stack**: trust anchors and revocation settings moved from the node to the verifier; the node no longer mounts anchors or sees a
  certificate and pins the verifier for email, phone and notary claims. Smoke test (synthetic CA, EGN-bearing certificate) passes: only listed
  claims attested, nothing personal in attestations or logs, bridge releases the verified name, birth date and age stay unreleased unless asked.
  441 tests.

### Planned (written down in `identity-system.md`, not testable yet)
- EU Digital Identity Wallet credentials (PID) with SD-JWT VC / mdoc selective disclosure over OpenID4VP as another method with the issuing
  state as trust anchor; depends on Bulgaria's wallet timing (unknown).
- Zero-knowledge proofs over a qualified signature (research).

### Open
- Real card + real Borica CA anchors still untried: needs the PIN and the CA certificates. The deployed server has no anchors, so its notary is off.
- The direct `eidas_qes` proof path (bridge sees the certificate) still exists as a library option but the stack no longer uses it.
- Birth date extraction covers Bulgarian EGN and the `dateOfBirth` attribute only.

## 2026-10-25 (verification) - SMS codes through a modem gateway

### Added
- **Phone verification** in the verification service (`sms_code`, assurance `low`, 6-digit codes, 10 minutes): the service
  queues the SMS (`verifiers/sms.py`, in memory, leased with retries) instead of sending it. `CodeVerifier` is now the shared
  base of `EmailVerifier` and `PhoneVerifier`; the API is generic over `/api/verify/{email|phone}/start|confirm` plus
  `GET .../{verification_id}/status` (queued | sent | failed + reason). Enabled by `NODETIDE_SMS_GATEWAY_TOKEN`;
  `NODETIDE_PHONE_ALLOWED` is the number mask (default `^\+359[0-9]{9}$`), rate limits 3/number, 3/identity, 10 total per hour.
- **Gateway endpoints**, bearer token (sha256-compared in constant time): `GET /api/gateway/sms/pending` (long poll, up to 30 s)
  and `POST /api/gateway/sms/{id}/result`. Chosen over a message broker: outbound-only HTTPS works behind NAT, nothing new to run.
- **`tools/sms-gateway/sms_gateway.py`**: the script for the home server with the USB modem (AT commands, text mode, pyserial).
  Modem-side safety: destination mask (default `+359` mobile), 10 per rolling 24 h (counted before the attempt, persisted in a
  0600 ledger with hashed numbers), 3 per number, ASCII-only text up to 160 characters, an id is never sent twice, expired
  messages are not sent, a wrong token stops it. `--dry-run [--dry-run-file]` and `--selftest-modem`. README with modem,
  ModemManager and systemd notes. 46 tests (`test_phone_verification`, `test_sms_gateway`) incl. a scripted fake serial port.
- Bridge: `NODETIDE_OIDC_PHONE_ISSUERS` (phone claims only); the test stack pins the verifier's issuer for email and phone.
  Wallet: add a phone claim, verify by SMS (shows queued / sent / refused). `init.sh` generates `SMS_GATEWAY_TOKEN`
  (`--upgrade` adds it). Smoke test covers the SMS path via the gateway script in dry-run mode.

### Open
- Not tried with a real modem yet (nothing to test against here): the AT handling is tested against a scripted serial port only.
  Expect device-specific quirks (SIM PIN, `AT+CSCS`, message-sent timing); `--selftest-modem` is the first thing to run.
- The queue is in memory: a service restart drops pending SMS (the codes expire anyway).

## 2026-10-25 (trust) - email verification is an independent service

### Changed
- **No self-verification.** A node no longer runs a verifier (`NODETIDE_EMAIL_VERIFIER` and `create_app(email_verifier=)` are gone,
  as are `/api/verify/*` on nodes) and the OIDC bridge trusts no issuer it was not told about. Email attestations are accepted
  only from identity hashes in the new `NODETIDE_OIDC_EMAIL_ISSUERS` (email only; `TRUSTED_ISSUERS` still covers all types).
- **`nodetide.verifiers.service`**: the verifier as a standalone aiohttp service (`python -m nodetide.verifiers.service`) with
  its own database, its own issuer identity, its own public address (the audience of key-control proofs), `/health`,
  `/api/auth/challenge`, `/api/verify/issuer` (now includes the issuer's sigchain) and `/api/verify/email/start|confirm`.
  `NODETIDE_VERIFIER_PUBLISH_ISSUER` writes the issuer hash for the operator to pin.
- **Wallet**: starts the verification at the service, then asks the person for the emailed code (it no longer reads a mailbox,
  so no ssh tunnel); stores the issuer's chain and sends it with the presentation (`issuer_sigchain`), so the bridge needs no lookup.
- **Test stack**: new `verifier` container (`nt-verifier.<domain>`, port 4575); its issuer hash goes through a shared volume
  into the node's entrypoint; SMTP settings in `.env` send real mail (default: catch-all mailpit). `init.sh --upgrade` adds
  the new settings. `local-wallet.sh --tunnel` is replaced by `--verifier`. Smoke test plays the person (reads the code from
  mailpit) and checks the attestation is signed by the service identity; passes locally.

### Open
- Old attestations made by the node's former embedded issuer are no longer trusted: verify email again in the wallet.
- Attestations are not yet revocable through the service API (the issuer can sign revocations; no endpoint).

## 2026-10-25 (sign-in) - "Open in wallet" links for web wallets

### Added
- `NODETIDE_OIDC_WALLET_URLS` (comma separated http(s) addresses): the sign-in page shows an "Open in wallet at <host>" link
  per wallet, pointing at `<wallet>/signin?link=<challenge address>` (never the fragment secret). The test stack sets it to its
  own wallet plus `http://localhost:4572`, so a wallet running on the user's machine (`local-wallet.sh`) works. The existing
  "Open Nodetide app" deep link (`nodetide://`) still only works where the native app is installed.
- Test wallet: `GET /signin?link=...` previews the request (approval stays a POST).

## 2026-10-25 (deployment) - Grafana as a guinea pig + local wallet

### Added
- **Grafana** (`nt-grafana.<domain>`, port 4574) in the test stack: stock Grafana with its generic OAuth provider
  (PKCE, client secret, userinfo), registered as client `grafana`. Login = identity hash, email = verified email or
  `<hash>@nodetide.invalid`, role Viewer; the local admin account stays. Verified end to end locally with the wallet.
- `init.sh --upgrade` adds the new settings (hosts, client secret, admin password) to an existing `.env` without
  touching existing secrets and rewrites `config/clients.json`; the workflow runs it before every deploy.
- Open design point discussed: sign-in works without the user's own node because the wallet submits its sigchain with the
  assertion; a bridge must be up though (an application trusts one issuer). Not yet tested with separate bridge/home nodes.

## 2026-10-25 (infrastructure) - Terraform for Hetzner + manual workflow

### Added
- **`deploy/test/terraform/`**: one Hetzner Cloud server (cloud-init installs Docker, creates the `deploy` user, key-only
  ssh), firewall (22/80/443/icmp), ssh key, optional A/AAAA records via `hcloud_zone_rrset`. Remote state in the
  existing AWS S3 bucket `nodetide-terraform-state` (shared with distriblog-infra, key `nodetide-test/terraform.tfstate`). Provider lock file includes linux/darwin hashes.
- **Availability-aware placement** (`modules/placement`, pure module with 10 offline `terraform test` cases): picks the
  first usable (server type, location) from preference lists using `hcloud_server_types[].locations[].available` /
  deprecation; fails with a per-pair table when nothing is available. The `hcloud_datacenters` data source was NOT used:
  it is deprecated and the API returns 410 after 2026-10-01.
- **`.github/workflows/test-stack.yml`**: manual `plan | apply | destroy` (+ optional `deploy_app`, per-run type/location
  overrides), `test-stack` environment for approvals, concurrency lock, ssh wait for cloud-init, reuses the server's
  existing `.env` so redeploys keep secrets and data. Required secrets/variables and `gh` commands: `deploy/test/terraform/README.md`.

### Also
- `deploy/test/local-wallet.sh`: run the test wallet on your own machine against a remote node (keys stay local;
  optional ssh tunnel to the test mailbox). `wallet/app.py` honours `HOST`.

### Open
- Applied once to a real account (cpx22@fsn1, cx23 was sold out everywhere); stack serves valid certificates.
- Workflow untested on GitHub (needs the secrets above and the `test-stack` environment).
- Domain / who serves 80 and 443 on the target is still undecided.

## 2026-10-25 (deployment) - docker-compose test stack

### Added
- **`deploy/test/`**: a compose stack for testing on a server: `node` (OIDC bridge, email verifier, eID proof
  verifier, explorer), `mailpit` (catches verification emails), `rp` (**oauth2-proxy**, a standard OIDC client,
  in front of a page that prints the claims it receives), `wallet` (a test stand-in for the Nodetide app: identity,
  claims, email verification through the test mailbox, statement signing, sign-in approval) and an optional Caddy
  `edge`. Self-contained image built from the repo (no ECR/base image). `init.sh` writes `.env` and
  `config/clients.json` with random secrets, `deploy.sh` copies + builds + starts over ssh, `smoke.py` plays a
  browser through the whole sign-in. See `deploy/test/README.md`.
- **Validated locally with Docker**: `smoke.py run` passes against the stack, including oauth2-proxy completing OIDC
  discovery, PKCE, confidential-client auth and RS256 id_token verification against the bridge, verified email and
  (synthetic CA) legal name released, nothing released when the wallet shares nothing, and the explorer not
  showing the email address.
- `nodetide eid sign-file STATEMENT` signs a canonical claim statement made elsewhere (the wallet) with the card;
  refuses anything that is not a Nodetide claim statement. `nodetide eid anchors` now also accepts a bare `.p7s`.
  Testkit: `sign-file`, `anchors [FILE] --out DIR`.
- `NODETIDE_OIDC_ALLOW_INSECURE=1` accepts http issuer / redirect URIs (local testing only).
- Root `.dockerignore` (keeps secrets and the testkit out of the build context).

### Fixed
- `golang/go.sum` was never committed, so the Go Docker build (and CI) failed with "missing go.sum entry";
  added it and dropped the unused `x/crypto` requirement.

### Findings about CI (not changed)
- "Build and Push Docker Images" failed on the last push for two reasons unrelated to the new code: the Python build
  could not find `nodetide:python-base-latest` in ECR (the base image workflow rebuilt it concurrently and has now
  succeeded, so a re-run should pass) and the Go build lacked `go.sum` (fixed above). The deploy jobs were
  skipped, so production was not touched.

### Not yet done
- **Not deployed to a server**: needs a target (ssh access, domain names, who serves ports 80/443).
- The real-card path through the stack (wallet statement -> `sign-file` -> upload) has been run only with the
  synthetic CA; the wallet's multipart upload form is untested with a browser.

## 2026-10-25 (latest) - signing testkit

### Added
- **`testkit/`** (scope deliberately limited to signing): `./testkit/run setup | selftest | token |
  claim | sign | anchors | verify | report | clean`. Isolated state in `.testkit/` via the new
  `NODETIDE_HOME` variable (the CLI's data directory), so `~/.nodetide` is never touched. `report` prints
  only technical facts (no names, ID numbers or hashes) and is the thing to paste when asking for help.
  The kit is itself tested (`python/tests/test_testkit.py`).
- `nodetide eid anchors ATTESTATION --out DIR` (`eidas/anchors.py`): follows the certificate's
  AIA links to collect the issuer chain, checks each certificate signed the one below, shows
  SHA-256 fingerprints and saves them as trust anchors only after interactive confirmation. Refuses
  private/loopback addresses unless `--allow-private`.

### Fixed
- Claim IDs could begin with `-`, so `nodetide claim ...` / `eid ...` parsed them as options. New
  claim IDs always start with a letter or digit.

### Scope note
- A broader testkit (demo node, simulated user app, simulated OIDC client, Go/UI runners) was started and
  removed at the owner's request: "only signing". If wanted later, the useful missing piece is a
  simulated user app, since no real client can yet approve OIDC sign-ins or verify an email claim.

## 2026-10-25 (later) - eID token tooling, name mapping, verified claims in OIDC

### Added
- **OIDC bridge releases verified claims** (`core/relying_party.py`, `oidc/provider.py`): scopes
  `profile`/`email`/`phone` map to `legal_name`/`email`/`phone` claims; the user's app sends
  `presentations` with its assertion; the bridge applies `ClaimRule`s (issuers, proof types,
  assurance, age, no recovery since) and returns standard claims plus an OpenID Connect for Identity
  Assurance `verified_claims` block. `display.claims_requested` in the challenge tells the app what
  is acceptable. Self-asserted genesis names are now labelled `name_verified: false`.
  Config: `NODETIDE_OIDC_TRUSTED_ISSUERS`, `NODETIDE_OIDC_NAME_MATCH`.
- **eID signing with PIN, rewritten against the real card** (`eidas/pkcs11.py`, `cli/claims.py`):
  slots and certificates are read without any PIN (`nodetide eid tokens`); the signing slot is chosen
  explicitly; the PIN is typed at a hidden prompt, tried once, never stored; locked / final-try /
  count-low states are checked first; keys that demand the PIN for every signature
  (`CKA_ALWAYS_AUTHENTICATE`) are handled with a context-specific login.
- **Certificate name mapping** (`eidas/certs.py`): givenName/surname plus the common name minus the
  surname (middle names, patronymics), and match strengths `exact` < `transliterated` <
  `approximate` (Alexey/Aleksey, Cyrillic vs Latin). `POST /api/claims/verify` takes `name_match`.

### Findings about the real token (no personal data)
- B-Trust (BORICA) card, Gemalto IDPrime MD, RSA 3072, SafeNet client libraries in `/usr/local/lib`
  (`libIDPrimePKCS11.dylib` is the default module). Certificate: qualified, QSCD, key usage
  content commitment, issued by "B-Trust Operational Qualified CA", subject has givenName, surname,
  serialNumber (national ID, never copied), CN with patronymic, and an email address.
- Two slots with separate PINs: slot 0 (authentication; certificate and public key visible, private
  key hidden before login) and slot 16 "(Digital Signature)". The qualified signing key is expected
  behind slot 16's PIN. Wrong PINs cost retries: nothing in the tool retries.
- The certificate carries an email address; verifying an `email` claim from it is possible later but
  qualified CAs do not necessarily prove mailbox control.

### Not yet done
- **Real signing has not been run**: needs the user's PIN. Expected: `eid tokens`, create a
  `legal_name` claim, `eid sign CLAIM_ID --slot 16`, `eid chain`, `eid verify --anchors DIR`
  with the B-Trust CA certificates from the provider.

## 2026-10-25 - Claims, attestations, OIDC bridge, explorer, native SSO

### Added
- **Native SSO** (`core/auth.py`, `api/auth/native.py`, `golang/auth/`): challenge/response login
  with `AuthRequest`/`AuthAssertion`, `authenticate` device capability, audience- and
  nonce-bound, domain-separated signatures. Python endpoints `/api/auth/{challenge,verify,login}`;
  the Go node has `challenge` and `verify` (sigchain must be supplied; no identity store yet).
  Python and Go agree byte-for-byte on canonical JSON and sigchain hashing (checked by a
  cross-language run, including claim events).
- **OIDC bridge** (`oidc/`): any Nodetide identity can sign in to standard OIDC apps
  (code flow + PKCE, RS256 id_token, `sub` = identity hash). Unknown or stale identities are queued
  in a persistent fetcher (`oidc/fetcher.py`, SSRF-guarded) and the user sees "failed for now".
  Enable with `NODETIDE_OIDC_ISSUER`; see README.
- **Explorer** (`explorer/`, `web/explorer/`): read-only API (`/api/explorer/*`) and a
  dependency-free UI at `/explorer` (`?node=` browses another node). Search index tables are kept
  up to date by `Storage.save_sigchain`; existing DBs are backfilled on open. `NODETIDE_EXPLORER=0`
  disables it.
- **Claims and attestations** replace `IdentityAssertion` (see spec section "Claims and
  Attestations"):
  - Sigchain events `ADD_CLAIM` / `REVOKE_CLAIM` (master or device with `manage_claims`), strict
    rules in `Sigchain.verify` and mirrored in Go (`golang/auth/sigchain.go`).
  - `core/claims.py`: salted commitments, value normalization, `ClaimDocument`, `Attestation`,
    `AttestationRevocation`, verification. Pinned commitment test vectors.
  - API `api/claims.py`: claims listing, signed publish/unpublish of claim documents,
    attestations, revocations, stateless `POST /api/claims/verify`.
  - **Email verification** (`verifiers/`): node-owned issuer identity (device key with
    `sign_identity`), SMTP / dev-log / memory mail senders, rate limits, single-use codes.
  - **eIDAS qualified e-signature proofs** (`eidas/`): CAdES-BES build/parse, QCStatements,
    certificate path validation (two-phase so strangers' certificates cannot make the node fetch
    URLs), Bulgarian name transliteration, PKCS#11 signer. Proof attestations are never stored or
    published because the embedded certificate carries personal identifiers.
  - CLI: `nodetide claim add|list|revoke|export`, `nodetide eid statement|attach|sign|tokens|chain|verify`.
- Trust delegations gained a claim-type `scope`; `GET /api/trust/calculate/{hash}?claim_type=`
  now computes path trust to an attestation issuer.

### Removed
- `IdentityAssertion`, `trust_assertions` table (dropped on open), `/api/trust/assertions`,
  `nodetide trust assert`, the web client's assertion UI. No migration: nothing was in use.

### Fixed
- `/api/auth/token` (legacy) called `Sigchain.from_events`, which does not exist.

### Verification at time of writing
- Python: full suite passes (`PYTHONPATH=src:. pytest tests`).
- Go: `gofmt`, `go vet`, `go test ./auth/` pass; cross-language run against the live Go server passes.
- Explorer UI exercised in jsdom against a seeded live node (no browser errors).
- **Not tested on real hardware or real credentials:** the PKCS#11 signer (only against a fake
  token), real Bulgarian eID certificates and trust anchors, real SMTP delivery.

### Open / next
- Try the real eID token: `nodetide eid tokens` then `eid sign`, or `eid statement` + the provider's
  signing app + `eid attach`; then `eid chain` / `eid verify` with the provider's CA certificates.
  Tokens whose key needs the PIN for every signature (`CKA_ALWAYS_AUTHENTICATE`) are not handled yet.
- No client UI yet (web, Android) for claims, signing assertions, or answering OIDC sign-ins; the
  OIDC bridge and email verifier are only exercised through the API and tests.
- OIDC bridge does not yet put verified claims (`name`, `email`) into id_tokens.
- Relying-party policy evaluation (`evaluate claim` in the spec) is described but only the pieces
  (`verify_attestation`, `/api/claims/verify`, trust path calculation) exist.
- The Go node has no identity store, sessions, OIDC bridge or explorer API.
- Python's `Sigchain.verify` accepts `social_recovery` without checking the trustee threshold (old
  TODO); Go rejects such chains.
- Sessions, challenges, OIDC attempts and pending email codes are in memory: run a single instance.
- Trusted-list handling for eIDAS is manual (operator supplies CA certificates); no CAdES-T
  timestamp checking, so proof attestations are kept short-lived.
- `golang/` has no `go.sum`; the Dockerfile resolves modules at build time.

### Working notes for the next session
- Tests: create a venv with the project dependencies plus `pytest pytest-asyncio`, then
  `cd python && PYTHONPATH=src:. pytest tests`. Go: `cd golang && go test ./auth/`.
- Tests that need PKI use the synthetic CA in `python/tests/pki.py`; never commit real certificates
  or signature files (they contain national ID numbers).
- Editing tools in this environment decoded `\uXXXX` escape sequences written in files; build such
  strings from a placeholder instead (see the canonical-JSON golden tests).
