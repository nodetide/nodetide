"""Publishing an identity's DNS records (core/state.py, core/dns_source.py) without copying them by hand.

Two ways to change a zone: RFC 2136 dynamic update through `nsupdate`, and the DNS provider plugins of acme.sh (which
every certbot-style tool already knows how to feed credentials to). See dns-publish.md.
"""
