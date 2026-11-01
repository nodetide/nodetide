"""Sigchain distribution by email: a responder that answers requests for chains, and a client that asks.

Email is an untrusted transport: a reply is only data, and the client checks it against the chain's own
signatures like anything fetched over HTTP. The work here is the request grammar, the abuse limits and the
reply format. See mailresponder/README in docs/email-distribution.md.
"""
