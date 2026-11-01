# Sigchains by email

Status: read-only responder and client implemented in `python/src/nodetide/mailresponder/`. Submission of events by email is deliberately not built.

## Why

A fallback transport for places where HTTP to a node is blocked or unavailable, and for devices that can only send and receive mail. Email is asynchronous and slow; that is acceptable for fetching a chain.

Chains verify themselves, so **the transport is untrusted**: a reply is only data, and the client checks it against the chain's signatures exactly as for HTTP. A node may withhold or lie by omission (see
"Behind, not wrong" in `sigchain-v2.md`); it cannot forge.

## Addressing

An identity lists a node's mailbox as a distribution point: `mailto:chains@node.example` (in `set_distribution`).

### Reading `mailto:` points

* **Accepted form:** one plain address, nothing else (`mailto:chains@node.example`). No `?subject=&cc=` (RFC 6068 headers can smuggle in recipients and content), no display name, list, percent-escapes or
  non-ASCII. `nodetide identity set-distribution` / `create` refuse anything else.
* **CLI:** `nodetide mail fetch <identity_hash>` takes the node from the identity's newest `mailto:` point in the stored chain (`--to` overrides).
* **Node:** the identity fetcher (sign-in of an unknown or newer identity) uses mail as a **last resort**: only after the HTTP sources did not satisfy the fetch, only for `mailto:` points in the identity's
  own signed chain (never for hints that arrive with a sign-in page), at most 2 requests per attempt. The request is sent at once and the answer taken whenever the poller sees it (`MailFetchService`): it
  has to be from the address asked, and is verified like any fetched chain before storing. Because we would be mailing addresses chosen by whoever published the chain, requests are rationed: one per
  address per hour, 30 per hour in all, none while an answer to the same request is awaited, never to ourselves. `NODETIDE_MAIL_FETCH=0` turns it off.

## Requests

Plain text, one command per line; everything else (greetings, signatures, quotes, HTML) is ignored. At most 5 commands per message; if the body has none, a command in the subject is used.

    GET chain <identity_hash> [light] [since=<control_event_hash> [from=<n>]]
    GET content <identity_hash> <seq>
    GET info

* `light`: the control chain only (sigchain-v2).
* `since=`: only the control events after that one; `from=n`: skip the first n content events (the asker holds them). An unknown `since` gets the whole chain.
* `GET content` returns one content event with its Merkle path to the control event that commits it.
* A message with no valid command gets a short help text.

## Replies

Threaded (`In-Reply-To`), `Auto-Submitted: auto-replied`, one JSON attachment per message: `{"kind": "chain" | "content" | "info" | "not_found" | "too_large", ...}`. Large answers are split into
`part`/`parts` (default 1 MB each, at most 6); an answer that would need more is refused with `too_large`, telling the asker to use `light` or `since`. Parts may arrive in any order; the client
refuses an incomplete set.

## Who is answered

* Only mail that the node's own mail server marked genuine: `Authentication-Results` with `dmarc=pass`, or `dkim=pass`/`spf=pass` for the From domain. With `NODETIDE_MAIL_TRUSTED_SERVERS` only headers
  written by those servers count (otherwise an outsider could add one).
* Only the **topmost** `Authentication-Results` header counts (and it must come from a trusted server when those are named): a mail server's milter prepends its verdict, but a header an outsider
  forged *with our server's name* is not removed and sits below it. Found by testing against a real docker-mailserver; covered by a test.
* Only to the single From address, never Reply-To. No reply to `Auto-Submitted`, `Precedence: bulk|list|junk`, list headers, a null return path, system senders, or ourselves.
* Each Message-ID once. Limits per sender (20/hour), per domain (100/hour), overall (600/hour), and a byte budget per sender (20 MB/hour); a refused request costs nothing against the other limits.
* Requests over 256 KB are dropped unread. Nothing in a request is executed or fetched.

## Privacy

The operator sees who asks about which identity (as an HTTP server sees addresses). Not addressed in v1; encrypting requests to the node would be a later step.

## Running it

Node: `NODETIDE_MAIL_RESPONDER=1`, `NODETIDE_MAIL_ADDRESS`, `NODETIDE_MAIL_IMAP_*`, `NODETIDE_SMTP_*` (see `mailresponder/config.py`; compose variables `MAIL_*` in `deploy/test`). The mailbox is polled
(default every 30 s); a message is marked seen *before* it is handled, so a crash loses a request rather than answering twice.

Client: `nodetide mail fetch <identity_hash> --to chains@node.example --from me@example.com` with `NODETIDE_SMTP_*` and `NODETIDE_MAIL_CLIENT_IMAP_*`.
