# Nodetide test stack

A docker-compose deployment for testing the whole thing on a server, with a real, independent
OIDC client in front of it. Nothing here is production: the wallet holds a development identity
in plain JSON and the mailbox is a catch-all.

```
browser ──► rp (oauth2-proxy) ──► "Signed in" page (shows the claims it received)
   │            │ standard OIDC: discovery, PKCE, client secret, RS256 id_token
   │            ▼
   ├──────► node (Nodetide: OIDC bridge, eID proof verifier, explorer; verifies nobody itself)
   │
   ├──────► verifier (independent email verification service, own issuer identity)
   │            │ one-time codes by SMTP
   │            ▼
   │         mailpit (catch-all: the codes land here unless SMTP_HOST is set in .env)
   └──────► wallet (stands in for the Nodetide app: identity, claims, signs-in on your behalf)
```

| Service | What it is | Public name | Local port |
|---|---|---|---|
| `node` | the Python node from this repo | `nt-node.<domain>` | 4570 |
| `rp` | oauth2-proxy + a page that prints the received claims | `nt-rp.<domain>` | 4571 |
| `wallet` | test wallet (HTTP basic auth, user `wallet`) | `nt-wallet.<domain>` | 4572 |
| `grafana` | Grafana with native OIDC: an ordinary third-party app as the guinea pig | `nt-grafana.<domain>` | 4574 |
| `verifier` | independent email verification service: own storage, own issuer identity | `nt-verifier.<domain>` | 4575 |
| `mailpit` | catch-all mailbox for the verifier's mail (private; SSH tunnel to read it) | - | 4573 |
| `edge` | optional Caddy with automatic HTTPS | all five | 80 / 443 |

Everything binds to `127.0.0.1`. The browser and the containers use the very same public URLs
(the containers reach them through `host-gateway`), so what works here is what a real client sees.

## Try it on your machine first

```sh
cd deploy/test
./init.sh --local                 # .env + config/, URLs under *.localtest.me:8080 (plain http)
docker compose up -d --build      # the edge profile is on in local mode
python3 smoke.py run              # needs the repo's Python env (nodetide, aiohttp)
```

Then open `http://nt-rp.localtest.me:8080`: you are sent to the Nodetide sign-in page. Open the wallet at
`http://nt-wallet.localtest.me:8080` (password: `WALLET_PASSWORD` in `.env`), paste the sign-in address,
choose which claims to reveal, approve, and the first tab shows what the application received.

`smoke.py prepare` makes a synthetic "eID" CA so the legal-name path runs without a card. It edits `.env`;
undo that (remove `ANCHORS_DIR` and `EIDAS_REVOCATION` lines) before real use. `deploy.sh` refuses to ship it.

## Deploy to a server

The server needs Docker with the compose plugin, three DNS names pointing at it, and either free ports
80/443 (use `--edge`) or an existing reverse proxy (see `nginx.conf.example`; the stack only listens locally).

```sh
./init.sh --domain example.org --edge      # drop --edge if nginx or similar already serves 80/443
./deploy.sh user@server                    # copies the sources, builds and starts on the server
./deploy.sh user@server --dry-run          # show what would be copied
./deploy.sh user@server --down             # stop (volumes are kept)
```

It builds on the server from the copied sources, so no registry or CI is involved. The mailbox is private:
`ssh -L 4573:127.0.0.1:4573 user@server` and open `http://localhost:4573`.

## Testing with your real eID card

The card stays on your machine; the server only ever sees signatures and certificates.

1. In the wallet, add a **legal name** claim (the names as on your certificate) and press **Create statement
   to sign**; download `statement-….txt`. You have 10 minutes to sign it.
2. On your machine: `./testkit/run sign-file ~/Downloads/statement-….txt` (asks for the digital-signature PIN;
   see `testkit/README.md` for the slots and PIN safety). It writes `statement-….txt.p7s`.
3. The server must trust your CA. Fetch it, check the fingerprints against the provider's published ones,
   and put it where the stack reads anchors:
   `./testkit/run anchors statement-….txt.p7s --out deploy/test/anchors` and
   `./deploy.sh user@server` (the node picks the anchors up on restart).
4. Upload the `.p7s` in the wallet. The node's verdict is shown next to the attestation. Revocation is checked
   online (`EIDAS_REVOCATION=hard-fail` in `.env`; use `soft-fail` while debugging a provider's OCSP).
5. Open the application at `nt-rp.<domain>` and approve the sign-in in the wallet with the legal name shared.
   The page lists `name_verified: true` and a `verified_claims` block naming the `eidas` trust framework.

The certificate inside the signature holds your national ID number. It travels to the server inside the wallet's
attestation and to nowhere else, and the node never stores it (proof attestations are not persisted); but the
wallet's volume does keep the attestation file, so `docker compose down -v` when you are done.

## Files

| | |
|---|---|
| `docker-compose.yml`, `Dockerfile`, `entrypoint.sh` | the stack and its self-contained image |
| `init.sh` | writes `.env` (random secrets) and `config/clients.json` |
| `deploy.sh` | copy + build + start on a server over ssh |
| `smoke.py` | end-to-end check, plays a browser through the standard OIDC client |
| `wallet/`, `echo/` | the test wallet and the page that prints received claims |
| `Caddyfile`, `nginx.conf.example` | TLS / routing for the three names |
| `anchors/` | CA certificates (PEM/DER) the node trusts for eID proofs; empty = proofs switched off |

## Security notes

- `.env`, `config/`, `anchors/` and `.smoke/` are git-ignored and excluded from the Docker build context.
- The wallet's keys are development keys; its password is the only thing between the internet and that identity.
- `NODETIDE_OIDC_ALLOW_INSECURE` (plain http) exists only for the local profile and is `0` for a domain.

## Server on Hetzner

`terraform/` creates the server (checking real availability) and `.github/workflows/test-stack.yml` applies it manually; see `terraform/README.md` for the required secrets.

## Wallet on your own machine

The wallet only makes outbound HTTPS calls to the node, so it can run locally and keep its keys on your machine
instead of on the server:

```sh
./local-wallet.sh https://nt-node.<domain>   # then open http://localhost:4572
```

It talks to the verification service at `nt-verifier.<domain>` (override with `--verifier URL`). State is in
`.local-wallet/` (git-ignored); the password is generated once and printed. Use the local wallet's identity for
sign-ins instead of the one on the server (the server's wallet service can simply stay unused).

On a Mac the script sets `WALLET_KEY_STORE=keychain`: `wallet.json` is then encrypted, and the key lives in the login
Keychain (service `nodetide-test-wallet`), so the private keys, claim values and attestations are never on disk in
clear. An existing plain `wallet.json` is encrypted on the next start. Losing the Keychain item makes the file
unreadable (the wallet stops instead of starting empty), so the identity is gone with it: this is a test wallet.

### As a macOS menu-bar app

`macos-app/build.sh` builds `Nodetide Wallet.app` (PyInstaller: Python and every dependency inside, no install needed on
the Mac that builds it for itself). It shows a 🪪 in the menu bar with **Open wallet**, **Change node…**, **Show data
folder** and **Quit**. On first start it asks for the node address (`https://nt-node.<domain>`; the verifier address is
derived as in `local-wallet.sh`). **Open wallet** opens the browser through a one-time link, so no password is typed.

- State is in `~/Library/Application Support/Nodetide Wallet/` and is encrypted with a key in the login Keychain; the
  generated HTTP password is in the Keychain too (service `nodetide-test-wallet-app`).
- It is only ad-hoc signed: another Mac shows a Gatekeeper warning (right-click, Open), and after a rebuild macOS may
  ask again for Keychain access.
- **Same identity on several devices.** On its first start the app asks whether this is your first wallet. Choose
  *Pair with my existing wallet* and the browser shows a code like `ABCDE-FGHJK`. In the wallet that holds your master
  key (the web one) open **Devices**, enter the code, compare the key fingerprint and add the device. The app then has
  the same identity, claims and attestations, adds claims as its own device and never holds the master key.
  (Details below.)

### Several devices, one identity (pairing)

An identity is its sigchain on the node; the wallet that holds the master key can authorize more devices on it, and a
device may add claims (the `manage_claims` capability) without ever holding the master key.

1. The new wallet makes its own device keys, shows a code (10 characters, about 49 bits) and publishes only its **public**
   keys in a slot named by the *hash* of the code (`POST /api/pairing` on the node, kept in memory for ten minutes).
2. You type the code into **Devices** on the wallet that holds the master key. It shows the new device's label and key
   fingerprint (the same one the new device displays); on confirming it appends an `add_device` event to the chain,
   publishes it, and leaves the claim values and attestations in the slot, sealed (NaCl box) to the new device's key.
3. The new wallet opens the answer and checks it before using it: the chain verifies, it lists this very device with
   `manage_claims`, the sender's key belongs to a device of the chain, and every claim value matches the commitment on the
   chain. Then it deletes the slot.

The node relays two small messages and can read neither the code nor the answer. This is a **one-time copy**: claims added
later on one device are not sent to the other (their commitments reach every device through the chain, the values do not).
Only the wallet with the master key can add devices; revoking devices and syncing values are not built yet.
To start over, *Start a new identity instead* on the pairing page makes a separate identity.

### Backup and recovery (the banner)

The wallet shows a red banner on its dashboard until the identity has (1) an **encrypted backup** and (2) **social recovery**:

1. **Backup.** *Protect your identity* downloads one file with the keys, claim values and attestations, encrypted with a password
   of 12+ characters (PBKDF2-SHA256, 1,000,000 rounds, AES-256-GCM) and read back before it counts. It goes out of date when claims or
   attestations change, and the banner returns. A new, empty wallet (the pairing page) can restore it. Keep the file and the password apart.
2. **Recovery.** Name at least 3 trustees (identity hashes that already exist on the node) and how many must agree (2 or more); the wallet
   that holds the master key publishes it as a `set_recovery` event. A wallet that does not hold the master key sees the state but sets it
   up from the one that does.

The web client at the node's root has the same banner, with the same rules; its backup also holds the master key.

## Grafana as a guinea pig

`nt-grafana.<domain>` is stock Grafana configured with its generic OAuth provider, the way any real application
would be: discovery URLs, PKCE, a client secret. Press **Sign in with Nodetide**, approve in the wallet and you land
in Grafana as a Viewer whose login is your identity hash (the email is the verified one if you shared it, otherwise a
placeholder `@nodetide.invalid`). The local `admin` account (password `GRAFANA_ADMIN_PASSWORD` in `.env`) stays
available so you cannot lock yourself out. On an existing server run `./init.sh --upgrade` once; it adds the
Grafana settings and keeps every existing secret. The workflow does that automatically.

## Email verification is a separate service

The `verifier` container is a party of its own: its own process, database and issuer identity, nothing shared with
the node except one public value. It emails a one-time code; **you read the email and type the code into the wallet**
(the wallet never reads a mailbox). The node trusts no issuer by default: the verifier writes its identity hash to a
shared file and the node's entrypoint pins it as `NODETIDE_OIDC_EMAIL_ISSUERS`, for email claims only.

- By default the mail goes to the catch-all `mailpit`, readable with `ssh -L 4573:127.0.0.1:4573 <server>` and
  http://localhost:4573.
- To receive real mail set `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` (starttls|ssl|none), `SMTP_USER`, `SMTP_PASSWORD` and
  `EMAIL_FROM` in `.env` on the server, then `docker compose up -d verifier`.

### Owned issuer (an organization with owners)

With `ISSUER_OWNED=1` in `.env` the issuing identity is an **organization with owners**: identities, each with a weight,
that found it and are the only ones who can recover its key or change the owners (approval of more than half of the
declared weight). Day to day the organization runs itself: its own key, held by the verifier container, authorizes the
signing device and replaces it later, no owner involved. If the server is lost or its key taken, the owners put a new key
in place; the organization, its history and the attestations it issued stay valid. An owner's own recovery (backup,
trustees) is the organization's recovery. Setting it up, once:

1. In the web client (`nt-node.<domain>`) create your identity, back it up and set up recovery (the banner).
2. Put `ISSUER_OWNED=1` and `ISSUER_OWNERS=<your identity hash>` (several: `hash:weight,hash:weight`) in `.env` on the
   server and `docker compose up -d verifier`. The verifier makes its keys and waits; its founding request is at
   `https://nt-verifier.<domain>/api/issuer/request` (also in `docker compose logs verifier`).
3. In the web client, **Organizations you own**: paste the request and approve it. With several owners each approves in
   turn and passes the result on; the last one publishes it. Copy the organization hash.
4. Put `ISSUER_ORG=<hash>` in `.env` and `docker compose up -d verifier`, then `docker compose restart node` (the node
   pins the issuer's hash at start). The verifier has the organization authorize its signing key by itself.

## SMS codes (phone claims)

The verification service also verifies **phone** claims: it queues an SMS and a gateway script with a USB modem
(`tools/sms-gateway/`, runs anywhere, only outbound HTTPS) fetches and sends it. `init.sh` generates
`SMS_GATEWAY_TOKEN` in `.env` (an existing server gets it from `init.sh --upgrade`); the same value goes to the gateway.
Numbers must match `PHONE_ALLOWED` (default `^\+359[0-9]{9}$`), and the gateway enforces its own mask and a count limit
(10 per 24 h by default). The wallet shows whether the SMS is queued, sent or was refused. Without a gateway the
messages stay queued and expire. `python3 smoke.py run` exercises the whole path with the gateway script in dry-run mode.

## eID: the verification service as notary

Legal name, birth date and "over 18" are proven from your eID card by the verification service acting as a notary; the
node and the applications never see your certificate or personal number.

1. In the wallet add the claims you want (legal name, birth date, "I am over 18"), tick the ones to attest and press
   *Create the statement to sign*. The statement names the notary and lists only what you ticked.
2. Sign it with the card on your machine: `nodetide eid sign-file notary-statement.txt` (shows the statement, asks the PIN).
3. Upload the `.p7s` in the wallet. It goes to the notary only and is not kept; the wallet keeps the attestations, which
   contain no certificate and nothing about the claims you left out.

### Trust anchors: published links, not copies

The CA certificates the notary trusts are **not in the repository**. `trust-anchors.json` is the published list of links to
where each provider publishes its certificates, each with the SHA-256 fingerprint it must have:

| CA | Published at | Pinned SHA-256 |
|---|---|---|
| B-Trust Operational Qualified CA (BORICA AD, Bulgaria; valid to 2033-05-31) | https://ca.b-trust.org/repository/B-TrustOperationalQCA_DER.crt (listed on https://www.b-trust.bg/en/queries/certification-chains-installation) | `499a9ca8b47ee84437f90b96fb40413ea293f9b3942a160837a0c67b0ec5ba0c` |

`./fetch-anchors.py` (stdlib only) downloads each link into `anchors/`, **refuses anything that does not match the pin**, and
cross-checks every run against the country's EU trusted list (https://crc.bg/files/_en/TSL_BG.xml, found through the EU list
of trusted lists at https://ec.europa.eu/tools/lotl/eu-lotl.xml): with `--strict` (the deploy workflow uses it) it stops if a
pinned certificate is not a *granted qualified-certificate service* there any more. The trusted list names the qualified CA
itself, not its root, so that intermediate is the anchor. The workflow runs it before every deploy and the verifier is
recreated when the set changes. To trust another provider add an entry (link + fingerprint you checked) and open a pull request.

How the pin was verified: downloaded from BORICA's repository over HTTPS, fingerprint computed locally, and found in the
Bulgarian trusted list as service *B-Trust Operational Qualified CA*, type QC, status granted. The list's XML signature is not
verified by the script (see the open point in `identity-system.md`), which is why the pin, not the list, is what is trusted.

`python3 smoke.py prepare` still makes a synthetic CA and points the verifier at it for the local test; `python3 smoke.py run`
covers the whole path, including that an unlisted birth date gets no attestation. Never deploy a `.env` that trusts it.
