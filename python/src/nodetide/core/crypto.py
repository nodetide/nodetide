"""Cryptographic primitives for identity and messaging.

Supports algorithm agility - each operation specifies its algorithm.
Default: Ed25519 for signing, X25519 for key exchange, XChaCha20-Poly1305 for encryption.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from nacl.public import PrivateKey as NaclPrivateKey
from nacl.public import PublicKey as NaclPublicKey
from nacl.public import Box
from nacl.signing import SigningKey as NaclSigningKey
from nacl.signing import VerifyKey as NaclVerifyKey
from nacl.exceptions import BadSignatureError
from nacl.utils import random as nacl_random


# Algorithm identifiers
ALG_ED25519 = "ed25519"
ALG_X25519 = "x25519"
ALG_XCHACHA20_POLY1305 = "xchacha20-poly1305"
HASH_SHA256 = "sha256"
HASH_BLAKE2B = "blake2b"

DEFAULT_SIGN_ALG = ALG_ED25519
DEFAULT_ENCRYPT_ALG = ALG_XCHACHA20_POLY1305
DEFAULT_HASH_ALG = HASH_SHA256


def hash_bytes(data: bytes, alg: str = DEFAULT_HASH_ALG) -> bytes:
    """Hash bytes using specified algorithm."""
    if alg == HASH_SHA256:
        return hashlib.sha256(data).digest()
    elif alg == HASH_BLAKE2B:
        return hashlib.blake2b(data).digest()
    else:
        raise ValueError(f"Unknown hash algorithm: {alg}")


def hash_hex(data: bytes, alg: str = DEFAULT_HASH_ALG) -> str:
    """Hash bytes and return hex string."""
    return hash_bytes(data, alg).hex()


def hash_json(obj: Any, alg: str = DEFAULT_HASH_ALG) -> str:
    """Hash a JSON-serializable object canonically."""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hash_hex(canonical.encode("utf-8"), alg)


def random_bytes(n: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    return secrets.token_bytes(n)


@dataclass(frozen=True)
class SigningKey:
    """Ed25519 signing key (private)."""

    _key: NaclSigningKey
    algorithm: str = ALG_ED25519

    @classmethod
    def generate(cls) -> SigningKey:
        """Generate a new random signing key."""
        return cls(_key=NaclSigningKey.generate())

    @classmethod
    def from_bytes(cls, data: bytes) -> SigningKey:
        """Load signing key from bytes."""
        return cls(_key=NaclSigningKey(data))

    @classmethod
    def from_hex(cls, hex_str: str) -> SigningKey:
        """Load signing key from hex string."""
        return cls.from_bytes(bytes.fromhex(hex_str))

    def to_bytes(self) -> bytes:
        """Export signing key as bytes."""
        return bytes(self._key)

    def to_hex(self) -> str:
        """Export signing key as hex string."""
        return self.to_bytes().hex()

    @property
    def verify_key(self) -> VerifyKey:
        """Get the corresponding verification (public) key."""
        return VerifyKey(_key=self._key.verify_key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message, returning signature bytes."""
        signed = self._key.sign(message)
        return signed.signature

    def sign_hex(self, message: bytes) -> str:
        """Sign a message, returning signature as hex string."""
        return self.sign(message).hex()


@dataclass(frozen=True)
class VerifyKey:
    """Ed25519 verification key (public)."""

    _key: NaclVerifyKey
    algorithm: str = ALG_ED25519

    @classmethod
    def from_bytes(cls, data: bytes) -> VerifyKey:
        """Load verification key from bytes."""
        return cls(_key=NaclVerifyKey(data))

    @classmethod
    def from_hex(cls, hex_str: str) -> VerifyKey:
        """Load verification key from hex string."""
        return cls.from_bytes(bytes.fromhex(hex_str))

    def to_bytes(self) -> bytes:
        """Export verification key as bytes."""
        return bytes(self._key)

    def to_hex(self) -> str:
        """Export verification key as hex string."""
        return self.to_bytes().hex()

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature. Returns True if valid, False otherwise."""
        try:
            self._key.verify(message, signature)
            return True
        except BadSignatureError:
            return False

    def verify_hex(self, message: bytes, signature_hex: str) -> bool:
        """Verify a signature given as hex string."""
        return self.verify(message, bytes.fromhex(signature_hex))

    @property
    def key_hash(self) -> str:
        """Hash of the public key, used for identity."""
        return hash_hex(self.to_bytes())


@dataclass(frozen=True)
class EncryptionPrivateKey:
    """X25519 private key for encryption/key exchange."""

    _key: NaclPrivateKey
    algorithm: str = ALG_X25519

    @classmethod
    def generate(cls) -> EncryptionPrivateKey:
        """Generate a new random encryption key."""
        return cls(_key=NaclPrivateKey.generate())

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptionPrivateKey:
        """Load private key from bytes."""
        return cls(_key=NaclPrivateKey(data))

    @classmethod
    def from_hex(cls, hex_str: str) -> EncryptionPrivateKey:
        """Load private key from hex string."""
        return cls.from_bytes(bytes.fromhex(hex_str))

    def to_bytes(self) -> bytes:
        """Export private key as bytes."""
        return bytes(self._key)

    def to_hex(self) -> str:
        """Export private key as hex string."""
        return self.to_bytes().hex()

    @property
    def public_key(self) -> EncryptionPublicKey:
        """Get the corresponding public key."""
        return EncryptionPublicKey(_key=self._key.public_key)

    def decrypt(self, ciphertext: bytes, sender_public_key: EncryptionPublicKey) -> bytes:
        """Decrypt a message from sender."""
        box = Box(self._key, sender_public_key._key)
        return box.decrypt(ciphertext)


@dataclass(frozen=True)
class EncryptionPublicKey:
    """X25519 public key for encryption."""

    _key: NaclPublicKey
    algorithm: str = ALG_X25519

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptionPublicKey:
        """Load public key from bytes."""
        return cls(_key=NaclPublicKey(data))

    @classmethod
    def from_hex(cls, hex_str: str) -> EncryptionPublicKey:
        """Load public key from hex string."""
        return cls.from_bytes(bytes.fromhex(hex_str))

    def to_bytes(self) -> bytes:
        """Export public key as bytes."""
        return bytes(self._key)

    def to_hex(self) -> str:
        """Export public key as hex string."""
        return self.to_bytes().hex()

    def encrypt(self, plaintext: bytes, sender_private_key: EncryptionPrivateKey) -> bytes:
        """Encrypt a message to this public key."""
        box = Box(sender_private_key._key, self._key)
        return box.encrypt(plaintext)

    @property
    def key_hash(self) -> str:
        """Hash of the public key."""
        return hash_hex(self.to_bytes())


@dataclass
class KeyPair:
    """Combined signing and encryption key pair."""

    signing_key: SigningKey
    encryption_key: EncryptionPrivateKey

    @classmethod
    def generate(cls) -> KeyPair:
        """Generate a new random key pair."""
        return cls(
            signing_key=SigningKey.generate(),
            encryption_key=EncryptionPrivateKey.generate(),
        )

    @property
    def verify_key(self) -> VerifyKey:
        """Get the public verification key."""
        return self.signing_key.verify_key

    @property
    def public_encryption_key(self) -> EncryptionPublicKey:
        """Get the public encryption key."""
        return self.encryption_key.public_key

    @property
    def identity_hash(self) -> str:
        """Hash of the signing public key, used as identity."""
        return self.verify_key.key_hash

    def sign(self, message: bytes) -> bytes:
        """Sign a message."""
        return self.signing_key.sign(message)

    def sign_hex(self, message: bytes) -> str:
        """Sign a message, return hex."""
        return self.signing_key.sign_hex(message)

    def to_dict(self) -> dict[str, str]:
        """Export key pair as dictionary (for storage)."""
        return {
            "signing_key": self.signing_key.to_hex(),
            "encryption_key": self.encryption_key.to_hex(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> KeyPair:
        """Load key pair from dictionary."""
        return cls(
            signing_key=SigningKey.from_hex(data["signing_key"]),
            encryption_key=EncryptionPrivateKey.from_hex(data["encryption_key"]),
        )


@dataclass(frozen=True)
class PublicKeyBundle:
    """Public keys for an identity or device."""

    verify_key: VerifyKey
    encryption_key: EncryptionPublicKey

    def to_dict(self) -> dict[str, str]:
        """Export as dictionary."""
        return {
            "verify_key": self.verify_key.to_hex(),
            "encryption_key": self.encryption_key.to_hex(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> PublicKeyBundle:
        """Load from dictionary."""
        return cls(
            verify_key=VerifyKey.from_hex(data["verify_key"]),
            encryption_key=EncryptionPublicKey.from_hex(data["encryption_key"]),
        )

    @property
    def key_hash(self) -> str:
        """Hash of the verification key."""
        return self.verify_key.key_hash


def encrypt_to_multiple(
    plaintext: bytes,
    recipients: list[EncryptionPublicKey],
    sender: EncryptionPrivateKey,
) -> dict[str, bytes]:
    """Encrypt a message to multiple recipients.

    Returns a dict mapping recipient key hash to ciphertext.
    Each recipient can decrypt independently.
    """
    result = {}
    for recipient in recipients:
        ciphertext = recipient.encrypt(plaintext, sender)
        result[recipient.key_hash] = ciphertext
    return result


def symmetric_encrypt(plaintext: bytes, key: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt with a symmetric key. Returns (ciphertext, key).

    If key is None, generates a random key.
    Uses XChaCha20-Poly1305 via NaCl SecretBox.
    """
    from nacl.secret import SecretBox

    if key is None:
        key = nacl_random(SecretBox.KEY_SIZE)

    box = SecretBox(key)
    ciphertext = box.encrypt(plaintext)
    return ciphertext, key


def symmetric_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt with a symmetric key."""
    from nacl.secret import SecretBox

    box = SecretBox(key)
    return box.decrypt(ciphertext)


ENCRYPTION_V1 = {
    "version": 1,
    "kdf": "pbkdf2-sha256",
    "kdf_iterations": 100000,
    "cipher": "aes-256-gcm",
    "salt_bytes": 16,
    "iv_bytes": 12,
}


# Backups leave the device and sit in a mailbox or a drive for years: derive their key much harder than the 100k
# used for the working copy of the keys (OWASP asks for 600k+ for PBKDF2-SHA256). The iteration count travels in the
# file, so every reader (Python, web client) honours it.
BACKUP_KDF_ITERATIONS = 1_000_000
MAX_KDF_ITERATIONS = 20_000_000  # refuse files that would make us burn minutes of CPU
MIN_BACKUP_PASSWORD = 12
_COMMON_PASSWORDS = {"password", "passwordpassword", "123456789012", "qwertyuiopas", "qwertyqwerty", "iloveyouiloveyou",
                     "administrator", "letmeinletmein"}


def weak_password_reason(password: str) -> str | None:
    """Why a backup password is too weak, or None. The web client applies the same rule."""
    if len(password) < MIN_BACKUP_PASSWORD:
        return f"Use at least {MIN_BACKUP_PASSWORD} characters (a few random words work well)."
    if len(set(password)) < 6 or password.isdigit() or password.lower() in _COMMON_PASSWORDS:
        return "That password is too easy to guess; use a longer, less predictable one."
    return None


def password_encrypt(plaintext: bytes, password: str, iterations: int | None = None) -> dict[str, Any]:
    """Encrypt data with a password using PBKDF2 + AES-256-GCM.

    This format is compatible with the web client's Crypto.encryptWithPassword.

    Returns a dict with encryption parameters and ciphertext for explicit format.
    """
    iterations = iterations or ENCRYPTION_V1["kdf_iterations"]
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Generate random salt and IV
    salt = random_bytes(ENCRYPTION_V1["salt_bytes"])
    iv = random_bytes(ENCRYPTION_V1["iv_bytes"])

    # Derive key from password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode("utf-8"))

    # Encrypt with AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    return {
        "v": ENCRYPTION_V1["version"],
        "kdf": ENCRYPTION_V1["kdf"],
        "kdf_iterations": iterations,
        "cipher": ENCRYPTION_V1["cipher"],
        "salt": salt.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
    }


def password_decrypt(encrypted: dict[str, Any], password: str) -> bytes:
    """Decrypt data encrypted with password_encrypt.

    Args:
        encrypted: Dict from password_encrypt with encryption parameters
        password: The password used for encryption

    Returns:
        Decrypted plaintext bytes

    Raises:
        ValueError: If decryption fails (wrong password or corrupted data)
    """
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    if encrypted.get("v") != 1:
        raise ValueError(f"Unsupported encryption version: {encrypted.get('v')}")

    salt = bytes.fromhex(encrypted["salt"])
    iv = bytes.fromhex(encrypted["iv"])
    ciphertext = bytes.fromhex(encrypted["ciphertext"])
    iterations = encrypted["kdf_iterations"]
    if not isinstance(iterations, int) or not 1 <= iterations <= MAX_KDF_ITERATIONS:
        raise ValueError("Unsupported key derivation cost")

    # Derive key from password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode("utf-8"))

    # Decrypt with AES-GCM
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(iv, ciphertext, None)
    except InvalidTag as e:
        raise ValueError("Decryption failed - wrong password or corrupted data") from e
