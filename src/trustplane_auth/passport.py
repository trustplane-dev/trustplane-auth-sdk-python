from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import _b64url, raw_public_key

DEFAULT_PASSPORT_TTL = timedelta(minutes=10)


@dataclass(frozen=True)
class PassportOptions:
    issuer: str
    subject: str
    audience: str
    trust_domain: str
    key_id: str
    private_key: Ed25519PrivateKey
    ttl: timedelta = DEFAULT_PASSPORT_TTL
    now: datetime | None = None
    jti: str = ""
    random_bytes: Callable[[int], bytes] = secrets.token_bytes


@dataclass(frozen=True)
class IssuedPassport:
    token: str
    issuer: str
    subject: str
    audience: str
    trust_domain: str
    key_id: str
    jti: str
    issued_at: datetime
    expires_at: datetime
    public_key_b64url: str
    key_binding: str = "software"
    passport_shape: str = "passport-v0.1"


def issue_passport(options: PassportOptions) -> IssuedPassport:
    required = {
        "issuer": options.issuer,
        "subject": options.subject,
        "audience": options.audience,
        "trust_domain": options.trust_domain,
        "kid": options.key_id,
    }
    for name, value in required.items():
        if value.strip() == "":
            raise ValueError(f"missing_{name}")
        if value != value.strip():
            raise ValueError(f"non_canonical_{name}")
    if options.ttl <= timedelta(0):
        raise ValueError("invalid_passport_ttl")
    now = options.now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    expires_at = now + options.ttl
    jti = options.jti.strip() or f"jti-{_b64url(options.random_bytes(16))}"
    public_key_b64url = _b64url(raw_public_key(options.private_key))
    header = {"alg": "EdDSA", "kid": options.key_id, "typ": "JWT"}
    claims = {
        "iss": options.issuer,
        "sub": options.subject,
        "aud": options.audience,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": jti,
        "trust_domain": options.trust_domain,
        "cnf": {
            "kid": public_key_b64url,
            "public_key_b64url": public_key_b64url,
            "key_binding": "software",
        },
    }
    unsigned = f"{_json_b64(header)}.{_json_b64(claims)}"
    token = f"{unsigned}.{_b64url(options.private_key.sign(unsigned.encode('ascii')))}"
    return IssuedPassport(
        token=token,
        issuer=options.issuer,
        subject=options.subject,
        audience=options.audience,
        trust_domain=options.trust_domain,
        key_id=options.key_id,
        jti=jti,
        issued_at=now,
        expires_at=expires_at,
        public_key_b64url=public_key_b64url,
    )


def _json_b64(value: object) -> str:
    return _b64url(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
