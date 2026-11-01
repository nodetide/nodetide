"""OIDC bridge configuration.

Environment:
    NODETIDE_OIDC_ISSUER           public https origin of this node (enables the bridge)
    NODETIDE_OIDC_CLIENTS_FILE     JSON file listing registered relying parties
    NODETIDE_OIDC_KEY_FILE         RSA signing key (PEM); created if missing
    NODETIDE_SEED_NODES            comma-separated node URLs to ask for unknown identities
    NODETIDE_OIDC_ALLOW_INSECURE   "1" to accept http:// issuer and redirect URIs (local testing only)
    NODETIDE_FETCH_ALLOW_PRIVATE   "1" to let the fetcher contact private/loopback addresses
    NODETIDE_OIDC_TRUSTED_ISSUERS  comma-separated identity hashes trusted to attest email/phone/legal_name
    NODETIDE_OIDC_EMAIL_ISSUERS    comma-separated identity hashes trusted to attest EMAIL claims only (e.g. an independent
                                   verification service); nothing is trusted unless it is named here or in TRUSTED_ISSUERS
    NODETIDE_OIDC_PHONE_ISSUERS    same, for PHONE claims only
    NODETIDE_OIDC_NOTARY_ISSUERS   same, for the eID-derived claims (legal_name, birthdate, age_over_18), which also need high assurance
    NODETIDE_OIDC_NAME_MATCH       exact|transliterated|approximate: how loosely a legal name may match an eID certificate
    NODETIDE_OIDC_WALLET_URLS      comma-separated web wallets (http(s) addresses) the sign-in page offers "open in" links for;
                                   a wallet on the user's own machine is typically http://localhost:4572

Clients file:
    [{"client_id": "grafana", "name": "Grafana",
      "redirect_uris": ["https://grafana.example.com/login/generic_oauth"],
      "client_secret_sha256": "<sha256 hex of the secret>"}]   # omit for public clients
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ConfigError(ValueError):
    """Invalid OIDC bridge configuration."""


def _is_secure_url(url: str, allow_insecure: bool = False) -> bool:
    """https, or http on a loopback host (development). allow_insecure accepts any http(s) URL."""
    parts = urlsplit(url)
    if not parts.hostname:
        return False
    if parts.scheme == "https":
        return True
    if parts.scheme == "http" and allow_insecure:
        return True
    return parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS


@dataclass(frozen=True)
class OIDCClient:
    """A registered relying party."""

    client_id: str
    name: str
    redirect_uris: tuple[str, ...]
    secret_sha256: str | None = None  # None => public client (PKCE required)

    @property
    def is_public(self) -> bool:
        return self.secret_sha256 is None

    def check_secret(self, secret: str | None) -> bool:
        """Constant-time client secret check. Public clients have no secret."""
        if self.secret_sha256 is None:
            return True
        if not secret:
            return False
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest, self.secret_sha256.lower())


@dataclass
class OIDCConfig:
    issuer: str
    clients: dict[str, OIDCClient]
    key_file: Path | None = None
    seed_nodes: list[str] = field(default_factory=list)
    allow_private_fetch: bool = False
    trusted_issuers: list[str] = field(default_factory=list)  # extra attestation issuers to accept
    email_issuers: list[str] = field(default_factory=list)  # trusted for email claims only
    phone_issuers: list[str] = field(default_factory=list)  # trusted for phone claims only
    notary_issuers: list[str] = field(default_factory=list)  # trusted for legal_name, birthdate, age_over_18
    name_match: str = "transliterated"
    allow_insecure: bool = False  # http:// issuer and redirect URIs: local testing only
    wallet_urls: list[str] = field(default_factory=list)  # web wallets offered on the sign-in page
    claim_rules: dict = field(default_factory=dict)  # explicit ClaimRule overrides by claim type
    issuers_file: str | None = None  # file holding one issuer hash that is trusted for email, phone and eID claims; re-read when it changes
    attempt_lifetime: int = 900  # how long a sign-in page stays usable
    code_lifetime: int = 120
    id_token_lifetime: int = 600
    access_token_lifetime: int = 3600

    def __post_init__(self) -> None:
        self.issuer = self.issuer.rstrip("/")
        if not _is_secure_url(self.issuer, self.allow_insecure):
            raise ConfigError("issuer must be an https URL (or http on localhost)")
        parts = urlsplit(self.issuer)
        if parts.query or parts.fragment:
            raise ConfigError("issuer must not contain a query or fragment")
        for issuer in [*self.trusted_issuers, *self.email_issuers, *self.phone_issuers, *self.notary_issuers]:
            if len(issuer) != 64 or any(c not in "0123456789abcdef" for c in issuer):
                raise ConfigError(f"trusted issuer {issuer!r} is not an identity hash")
        for wallet in self.wallet_urls:
            if not _is_secure_url(wallet, allow_insecure=True) or urlsplit(wallet).query or urlsplit(wallet).fragment:
                raise ConfigError(f"wallet URL {wallet!r} must be an http(s) address without query or fragment")
        self.wallet_urls = [w.rstrip("/") for w in self.wallet_urls]
        if self.name_match not in ("exact", "transliterated", "approximate"):
            raise ConfigError("name_match must be exact, transliterated or approximate")

    @classmethod
    def load_clients(cls, path: str | Path, allow_insecure: bool = False) -> dict[str, OIDCClient]:
        try:
            raw = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise ConfigError(f"Cannot read clients file {path}: {e}") from e
        if not isinstance(raw, list):
            raise ConfigError("clients file must contain a JSON list")

        clients: dict[str, OIDCClient] = {}
        for entry in raw:
            if not isinstance(entry, dict):
                raise ConfigError("each client must be an object")
            client_id = entry.get("client_id")
            uris = entry.get("redirect_uris")
            if not isinstance(client_id, str) or not client_id:
                raise ConfigError("client_id is required")
            if client_id in clients:
                raise ConfigError(f"duplicate client_id {client_id}")
            if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
                raise ConfigError(f"{client_id}: redirect_uris must be a non-empty list")
            for uri in uris:
                if not _is_secure_url(uri, allow_insecure) or urlsplit(uri).fragment:
                    raise ConfigError(f"{client_id}: insecure or invalid redirect_uri {uri}")
            secret = entry.get("client_secret_sha256")
            if secret is not None and (
                not isinstance(secret, str) or len(secret) != 64
                or any(c not in "0123456789abcdefABCDEF" for c in secret)
            ):
                raise ConfigError(f"{client_id}: client_secret_sha256 must be 64 hex chars")
            clients[client_id] = OIDCClient(
                client_id=client_id,
                name=str(entry.get("name") or client_id),
                redirect_uris=tuple(uris),
                secret_sha256=secret,
            )
        return clients

    @classmethod
    def from_env(
        cls,
        issuer: str | None = None,
        default_key_dir: Path | None = None,
    ) -> OIDCConfig | None:
        """Build config from the environment. Returns None if no issuer is set."""
        issuer = issuer or os.environ.get("NODETIDE_OIDC_ISSUER")
        if not issuer:
            return None

        clients_file = os.environ.get("NODETIDE_OIDC_CLIENTS_FILE")
        insecure = os.environ.get("NODETIDE_OIDC_ALLOW_INSECURE") == "1"
        clients = cls.load_clients(clients_file, insecure) if clients_file else {}

        key_file = os.environ.get("NODETIDE_OIDC_KEY_FILE")
        if key_file:
            key_path: Path | None = Path(key_file)
        elif default_key_dir is not None:
            key_path = default_key_dir / "oidc_signing_key.pem"
        else:
            key_path = None

        seeds = [s.strip() for s in os.environ.get("NODETIDE_SEED_NODES", "").split(",") if s.strip()]
        return cls(
            issuer=issuer,
            clients=clients,
            key_file=key_path,
            seed_nodes=seeds,
            allow_private_fetch=os.environ.get("NODETIDE_FETCH_ALLOW_PRIVATE") == "1",
            trusted_issuers=[
                h.strip().lower() for h in os.environ.get("NODETIDE_OIDC_TRUSTED_ISSUERS", "").split(",") if h.strip()
            ],
            email_issuers=[
                h.strip().lower() for h in os.environ.get("NODETIDE_OIDC_EMAIL_ISSUERS", "").split(",") if h.strip()
            ],
            phone_issuers=[
                h.strip().lower() for h in os.environ.get("NODETIDE_OIDC_PHONE_ISSUERS", "").split(",") if h.strip()
            ],
            notary_issuers=[
                h.strip().lower() for h in os.environ.get("NODETIDE_OIDC_NOTARY_ISSUERS", "").split(",") if h.strip()
            ],
            name_match=os.environ.get("NODETIDE_OIDC_NAME_MATCH", "transliterated"),
            allow_insecure=insecure,
            wallet_urls=[w.strip() for w in os.environ.get("NODETIDE_OIDC_WALLET_URLS", "").split(",") if w.strip()],
            issuers_file=os.environ.get("NODETIDE_OIDC_ISSUERS_FILE") or None,
        )
