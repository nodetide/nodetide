# Publishing DNS records without copying them by hand

`nodetide identity dns-record` prints the records of an identity (state-record.md: the signed state, the plain list of places, the optional entry at `_nodetide.<domain>`). `nodetide identity dns-publish` puts
them into the zone, two ways:

## nsupdate (RFC 2136 dynamic update)

    nodetide identity dns-publish --method nsupdate --nsupdate-server ns1.example.org --nsupdate-key-file ./tsig.key --zone example.org

The primary name server must accept updates for the zone from your TSIG key (`allow-update { key "..."; }` in BIND, `acl`/`update_acl` in Knot, ...). The key is a file as `nsupdate -k` reads it, or
`--nsupdate-key [algorithm:]name:secret` / the environment variable `NODETIDE_NSUPDATE_KEY`; a key given this way goes into a private temporary file, never onto a command line where `ps` would show it.
The update is one transaction. Not installed? `nsupdate` is part of BIND's tools (`dnsutils`, `bind-utils`, `bind9-dnsutils`, `knot-dnsutils`).

To do it yourself: `nodetide identity dns-record --format nsupdate` prints the script (also on My Identity > Publish in the web client, "nsupdate script"), and `--format zone` prints zone-file lines.

## DNS provider plugins of acme.sh

    CF_Token=... nodetide identity dns-publish --method acme --acme-plugin dns_cf

[acme.sh's dnsapi](https://github.com/acmesh-official/acme.sh/tree/master/dnsapi) has plugins for some two hundred providers. They are shell files defining `dns_<name>_add <fulldomain> <txtvalue>` and
`dns_<name>_rm <fulldomain> <txtvalue>`, and they need acme.sh's helper functions, so the tool **sources acme.sh as a library** (its `main` only prints help when called with no arguments) and then calls the
plugin. Consequences worth knowing:

* **acme.sh is not bundled and not downloaded.** Point to an installation you trust: `--acme-home`, default `$LE_WORKING_DIR` or `~/.acme.sh`. The plugin runs with your provider's credentials, so it is your
  choice which code that is; the CI of this project uses the tag `3.1.6`.
* **Credentials come from the environment**, exactly as for acme.sh. `nodetide dns plugins` lists the installed plugins and `nodetide dns plugins dns_cf` shows the variables one reads. The plugin may save them to the
  `account.conf` of that acme.sh home, as it does when acme.sh itself runs it.
* The value reaches the plugin through the environment variable `NT_VALUE`, not on a command line.
* A plugin adds or removes **one value at a time**, so the order is: add the new values, then remove the old ones, so a reader always finds something.
* **Compatibility is the plugin's business.** These values are longer than the tokens acme.sh normally publishes (the signed state is about 1 to 1.5 KB) and contain spaces, `;`, `=` and `:`. Plugins that build requests
  by hand without encoding, or providers that cap TXT length or split long values differently, may mis-handle them. It was tried here against a stand-in plugin and the real acme.sh loader, not against live providers.
  `--dry-run` shows what would be sent; check the result with `nodetide identity dns-lookup <domain> <hash>`.

## What is touched

Only values this identity wrote. At the identity's own name (`<id32>._nodetide.<domain>`) that is its signed state and plain list; at the domain's name (`_nodetide.<domain>`) only the plain entry for this
identity: other identities' entries and anything else stay. Current values are read from the name server being updated (nsupdate) or the system resolver (plugins), compared with what should be there, and only
the difference is applied; an up-to-date zone changes nothing. `--remove` takes everything of ours down. `--dry-run` shows the plan.

## Tested

Unit tests cover the script, quoting, keys and the diff. The live tests (`tests/test_dns_publish_live.py`, a CI job) run a real BIND in Docker with a TSIG key: publish, a second run changing nothing, an update replacing
the old state, a foreign entry surviving, removal, a wrong key being refused; and the real acme.sh loading a plugin and saving its credentials.
