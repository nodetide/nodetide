# Hetzner Cloud server for the test stack

Terraform that creates one Hetzner Cloud server (Docker preinstalled), a firewall (22, 80, 443, ping), an ssh key
and, optionally, the DNS records for `nt-node.`, `nt-rp.` and `nt-wallet.<domain>`. The docker-compose stack from
`deploy/test/` is then deployed onto it.

## Availability

Hetzner capacity is limited and varies by location. Nothing is hard-coded: `modules/placement` reads
`hcloud_server_types` (per location: *available* = not temporarily sold out, *deprecated*) and picks the first pair
from `server_type_preference` x `location_preference` that is usable right now. For each type, all locations are
tried before the next type. If nothing qualifies, the plan fails with a table saying why for every pair, and where
the preferred types are available outside your location list.

```
Checked (type, location, state):
  cx23     fsn1  temporarily unavailable (sold out)
  cx23     nbg1  available
```

The placement is evaluated at every plan, so the **apply workflow plans and applies in the same run** (a saved plan,
no gap). Once a server exists its type and location are ignored, so a stock change never replaces it. Caveat: the
availability check still runs on every plan, so if *everything* in your lists is sold out the plan fails even for an
existing server; widen the lists for that run (`server_types` / `locations` inputs).

The selection logic has offline tests: `cd modules/placement && terraform init -backend=false && terraform test`
(also run by the workflow).

## Authentication needed

Everything is set in the GitHub repository: **Settings -> Secrets and variables -> Actions**. Create an environment
named `test-stack` (Settings -> Environments) and optionally add yourself as required reviewer, so apply/destroy
wait for an approval click.

| Kind | Name | What | Where it comes from |
|---|---|---|---|
| secret | `HCLOUD_TOKEN` | Hetzner Cloud API token, **Read & Write** | Hetzner Console -> your project -> Security -> API tokens |
| variable | `AWS_ACCESS_KEY_ID` | access key ID (an identifier, not a secret: keep it a variable so it stays visible) | IAM user with read/write on `nodetide-terraform-state` (key `nodetide-test/*`) |
| secret | `AWS_SECRET_ACCESS_KEY` | the matching secret key | same IAM access key |
| variable | `DEPLOY_SSH_PUBLIC_KEY` | public half of the deploy key | see below |
| secret | `DEPLOY_SSH_PRIVATE_KEY` | private half (only for `deploy_app`) | see below |
| variable | `TEST_DOMAIN` | FQDN without trailing dot, e.g. `test.example.org`; the hosts become `nt-node.<it>`, `nt-rp.<it>`, `nt-wallet.<it>` (optional for plan/apply; required for `deploy_app`) | your domain |
| variable | `TEST_DNS_ZONE` | Hetzner DNS zone that is `TEST_DOMAIN` itself or a parent of it, e.g. `example.org` (optional: empty = create the DNS records yourself) | Hetzner Console -> DNS |
| variable | `TEST_CREATE_DNS_ZONE` | `true` = Terraform creates the zone named in `TEST_DNS_ZONE` (the apply prints `dns_nameservers`: set those at the registrar once, e.g. for a registrar without an API) | |

Commands (with the `gh` CLI, run once):

```sh
# 1. deploy key pair (dedicated; no passphrase because CI uses it)
ssh-keygen -t ed25519 -N '' -C nodetide-test-deploy -f ./nodetide-test-deploy
gh variable set DEPLOY_SSH_PUBLIC_KEY < nodetide-test-deploy.pub
gh secret   set DEPLOY_SSH_PRIVATE_KEY < nodetide-test-deploy
shred -u nodetide-test-deploy 2>/dev/null || rm -P nodetide-test-deploy   # keep nothing locally unless you want ssh access

# 2. Hetzner token (prompts, so it does not land in shell history)
gh secret set HCLOUD_TOKEN

# 3. state bucket: AWS S3 `nodetide-terraform-state` (shared with distriblog-infra)
gh variable set AWS_ACCESS_KEY_ID --body AKIA...
gh secret   set AWS_SECRET_ACCESS_KEY

# 4. optional: domain and DNS
gh variable set TEST_DOMAIN   --body test.example.org
gh variable set TEST_DNS_ZONE --body example.org
```

Use a Hetzner project dedicated to testing: the token can create and delete anything in it. State contains the
server IPs only (no secrets are managed by Terraform).

## Running it

GitHub -> Actions -> **Test stack (Hetzner)** -> Run workflow:

| action | effect |
|---|---|
| `plan` | tests + validate + plan, changes nothing (start here) |
| `apply` | creates / updates the server; with `deploy_app` also installs the stack (`init.sh --domain ... --edge` on first run, the server's existing `.env` is reused afterwards, so secrets and data survive redeploys) |
| `destroy` | removes server, firewall, key and DNS records (the data volumes go with the server) |

`server_types` / `locations` override the preference lists for one run (comma separated, e.g. `cax11,cx23` /
`hel1,fsn1`).

Without a domain the server still comes up; deploy by hand with `deploy/test/deploy.sh deploy@<ip>`.

## Local use

```sh
cp terraform.tfvars.example terraform.tfvars        # set ssh_public_key (and domain/dns_zone)
export HCLOUD_TOKEN=...
terraform init -backend=false      # local state; omit the flag (with AWS credentials set) to use the shared S3 state
terraform plan
```

The first boot (packages, Docker) takes a couple of minutes; the server creates `/var/lib/cloud/instance/nodetide-ready`
when finished.

## Notes

- SSH is open to the world by default (CI runners have no fixed address): password login is off, only the deploy key
  works. Set `ssh_allowed_cidrs` to narrow it.
- `user_data`, `image`, `ssh_keys`, `server_type` and `location` are ignored after creation so later edits do not rebuild a server holding data.
  To apply such a change, `destroy` and `apply`.
- The synthetic test CA is never trusted here; use real eID trust anchors only as described in `deploy/test/README.md`.
