from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class LocalEd25519Key:
    private_key: Ed25519PrivateKey
    private_key_b64url: str
    public_key_b64url: str
    fingerprint_sha256: str
    key_binding: str = "software"


def private_key_from_base64url(value: str) -> Ed25519PrivateKey:
    canonical = value.strip()
    if not _BASE64URL_RE.fullmatch(canonical):
        raise ValueError("invalid_private_key_base64url")
    try:
        decoded = base64.urlsafe_b64decode(canonical + "=" * ((4 - len(canonical) % 4) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid_private_key_base64url") from exc
    if _b64url(decoded) != canonical:
        raise ValueError("non_canonical_private_key_base64url")
    if len(decoded) == 32:
        return Ed25519PrivateKey.from_private_bytes(decoded)
    if len(decoded) == 64:
        key = Ed25519PrivateKey.from_private_bytes(decoded[:32])
        if raw_public_key(key) != decoded[32:]:
            raise ValueError("private_key_public_key_mismatch")
        return key
    raise ValueError(f"invalid_private_key_size: {len(decoded)}")


def export_local_ed25519_key(private_key: Ed25519PrivateKey) -> LocalEd25519Key:
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_key = raw_public_key(private_key)
    return LocalEd25519Key(
        private_key=private_key,
        private_key_b64url=_b64url(seed + public_key),
        public_key_b64url=_b64url(public_key),
        fingerprint_sha256=f"sha256:{hashlib.sha256(public_key).hexdigest()}",
    )


def generate_local_ed25519_key() -> LocalEd25519Key:
    return export_local_ed25519_key(Ed25519PrivateKey.generate())


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
