# Finding nodes on the local network (mDNS)

Status: announcing and browsing existed (`relay/mdns.py`, `nodetide relay discover`); this adds what a node says, and the node using what it finds.

## What a node announces

`_nodetide._tcp.local.` with TXT `version=1`, `path=/api`, `scheme=http|https`, and optionally `ids=<hash>[,<hash>...]`: up to 3 identity hashes the operator chose to advertise
(`NODETIDE_MDNS_IDENTITIES`), so a client can find *its* node by its own hash. Everybody on the LAN can read this, so nothing is advertised by default. The chain head is deliberately not
announced: it changes, and a client asks the node (`/api/identities/<hash>`) anyway. Announcing is off unless `NODETIDE_MDNS=1`.

## Using discovered nodes (`NODETIDE_MDNS_DISCOVER=1`, off by default)

The identity fetcher (sign-in of an unknown or newer identity) tries, in order: the identity's HTTP distribution points and the seed nodes, **nodes found on the LAN**, then `mailto:` points
(`email-distribution.md`). A chain from any of them is verified like every other before it is stored.

Multicast is unauthenticated, so an announcement must not be able to aim the node's requests anywhere. A discovered node is used only when its address is **on a network this machine is attached to**
(from the interface list), is not our own address, loopback, link-local metadata (`169.254.169.254`) or multicast; at most 8; IPv4 only; and the only request ever made is
`GET /api/identities/<hash>/sigchain` (no redirects, 2 MB cap, short timeout). What a hostile LAN device can still do is withhold data or see which identity is asked for.

## Android

The Relays screen browses while it is open (`RelayDiscoveryService`, NsdManager; resolves are queued because Android allows one at a time). Every announcement passes `Lan.fromAnnouncement`
(`android/protocol`, tested on the JVM): version 1, a plain IPv4 address on a local range, a valid port. If the current account's hash is among a node's advertised `ids`, a card offers **"Use"**
for it, with the plain statement that this is only what the node announces: anyone on the network can announce any identity, so the user confirms by recognising the address. Nothing is
connected automatically.

Cleartext http is permitted at the platform level (the network security config cannot express "private ranges only", and its old CIDR entries matched nothing), so the app enforces it:
`Lan.cleartextAllowed` is applied to every request by `ApiClient` and to a manually typed address; http is only for local addresses and `.local` names, https for anything else, redirects are not followed.

## Not done

The web client cannot use mDNS at all. Android 17 introduces a local-network permission for apps targeting its API level (not needed at target 36; to add when the target moves). The Android part has
been compiled and its pure logic tested, but not run on a device.
