from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .transcript import (
    DEFAULT_AUTHORIZATION_TYPE,
    HEADER_AUTHORIZATION,
    HEADER_BODY_SHA256,
    HEADER_NONCE,
    HEADER_PROOF,
    HEADER_TRANSCRIPT_SHA256,
    SOFTWARE_KEY_BINDING,
    RequestInput,
    build_request,
)

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class ProofInput:
    request: RequestInput | Mapping[str, Any]
    passport_token: str
    private_key: Ed25519PrivateKey | bytes | str
    key_id: str = ""
    signer_class: str = ""


@dataclass(frozen=True)
class SignedRequest:
    transcript_sha256: str
    body_sha256: str
    headers: dict[str, str]
    canonical_lines: tuple[str, ...]
    key_id: str
    signer_class: str


@dataclass(frozen=True)
class _PassportBinding:
    audience: str
    jti: str
    issued_at: int
    key_id: str
    key_binding: str
    public_key_b64url: str


def sign_request(
    proof: ProofInput | None = None,
    *,
    request: RequestInput | Mapping[str, Any] | None = None,
    passport_token: str = "",
    private_key: Ed25519PrivateKey | bytes | str | None = None,
    key_id: str = "",
    signer_class: str = "",
) -> SignedRequest:
    if proof is not None:
        request = proof.request
        passport_token = proof.passport_token
        private_key = proof.private_key
        key_id = proof.key_id
        signer_class = proof.signer_class

    token = passport_token.strip()
    if token == "":
        raise ValueError("missing_passport_token")
    if private_key is None:
        raise ValueError("missing_private_key")

    key = _load_private_key(private_key)
    claims = _parse_passport_binding(token)
    _validate_passport_binding(claims, key)
    request_input = _coerce_signing_request(request)
    _validate_signing_consistency(request_input, key_id, signer_class, claims)

    request_data = {
        **request_input.__dict__,
        "audience": claims.audience,
        "passport_jti": claims.jti,
        "issued_at": None,
        "issued_at_unix": claims.issued_at,
        "key_binding": SOFTWARE_KEY_BINDING,
    }
    material = build_request(request_data)
    digest = bytes.fromhex(material.transcript_sha256)
    proof_header = _base64url_no_padding(key.sign(digest))

    return SignedRequest(
        transcript_sha256=material.transcript_sha256,
        body_sha256=material.body_sha256,
        headers={
            HEADER_AUTHORIZATION: f"{DEFAULT_AUTHORIZATION_TYPE} {token}",
            HEADER_TRANSCRIPT_SHA256: material.transcript_sha256,
            HEADER_PROOF: proof_header,
            HEADER_NONCE: str(request_data["nonce"]).strip(),
            HEADER_BODY_SHA256: material.body_sha256,
        },
        canonical_lines=material.canonical_lines,
        key_id=claims.key_id,
        signer_class=SOFTWARE_KEY_BINDING,
    )


def _load_private_key(raw: Ed25519PrivateKey | bytes | str) -> Ed25519PrivateKey:
    if isinstance(raw, Ed25519PrivateKey):
        return raw
    key_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    if key_bytes.strip().startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("invalid_private_key_type")
        return key
    if len(key_bytes) == 32:
        return Ed25519PrivateKey.from_private_bytes(key_bytes)
    raise ValueError(f"invalid_private_key_size: {len(key_bytes)}")


def _parse_passport_binding(token: str) -> _PassportBinding:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("invalid_passport_token")
    try:
        payload_raw = _decode_base64url(parts[1])
        payload = json.loads(payload_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid_passport_token: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid_passport_token")

    cnf_raw = payload.get("cnf")
    cnf = cnf_raw if isinstance(cnf_raw, dict) else {}
    issued_at = _numeric_unix(payload.get("iat"))
    if issued_at is None:
        raise ValueError("passport_missing_iat")

    return _PassportBinding(
        audience=_audience_string(payload.get("aud")),
        jti=_claim_string(payload.get("jti")),
        issued_at=issued_at,
        key_id=_claim_string(cnf.get("kid")),
        key_binding=_claim_string(cnf.get("key_binding")),
        public_key_b64url=_claim_string(cnf.get("public_key_b64url")),
    )


def _validate_passport_binding(claims: _PassportBinding, private_key: Ed25519PrivateKey) -> None:
    required = {
        "aud": claims.audience,
        "jti": claims.jti,
        "cnf_kid": claims.key_id,
        "cnf_key_binding": claims.key_binding,
        "cnf_public_key_b64url": claims.public_key_b64url,
    }
    for name, value in required.items():
        if value.strip() == "":
            raise ValueError(f"passport_missing_{name}")
        if value != value.strip():
            raise ValueError(f"passport_non_canonical_{name}")

    if claims.key_binding != SOFTWARE_KEY_BINDING:
        raise ValueError("local_raw_key_supports_only_software_key_binding")

    public_key = _decode_canonical_base64url(
        claims.public_key_b64url,
        "cnf_public_key_b64url",
    )
    if len(public_key) != 32:
        raise ValueError(f"invalid_cnf_public_key_size: {len(public_key)}")

    private_public_key = _raw_public_key(private_key.public_key())
    if public_key != private_public_key:
        raise ValueError("cnf_public_key_mismatch")


def _validate_signing_consistency(
    request: RequestInput,
    key_id: str,
    signer_class: str,
    claims: _PassportBinding,
) -> None:
    _validate_optional_software(request.key_binding)
    _validate_optional_software(signer_class)

    if request.audience.strip() != "" and request.audience.strip() != claims.audience:
        raise ValueError("passport_audience_mismatch")
    if request.passport_jti.strip() != "" and request.passport_jti.strip() != claims.jti:
        raise ValueError("passport_jti_mismatch")
    if request.issued_at_unix != 0 and request.issued_at_unix != claims.issued_at:
        raise ValueError("passport_iat_mismatch")
    if request.issued_at is not None and int(_timestamp(request.issued_at)) != claims.issued_at:
        raise ValueError("passport_iat_mismatch")
    if key_id.strip() != "" and key_id.strip() != claims.key_id:
        raise ValueError("passport_cnf_kid_mismatch")


def _validate_optional_software(value: str) -> None:
    if value.strip() == "":
        return
    if value != SOFTWARE_KEY_BINDING:
        raise ValueError("local_raw_key_supports_only_software_key_binding")


def _coerce_signing_request(request: RequestInput | Mapping[str, Any] | None) -> RequestInput:
    if request is None:
        return RequestInput()
    if isinstance(request, RequestInput):
        return request
    return RequestInput(**dict(request))


def _decode_canonical_base64url(value: str, name: str) -> bytes:
    try:
        decoded = _decode_base64url(value)
    except ValueError as exc:
        raise ValueError(f"invalid_{name}: {exc}") from exc
    if _base64url_no_padding(decoded) != value:
        raise ValueError(f"non_canonical_{name}")
    return decoded


def _decode_base64url(value: str) -> bytes:
    if not _BASE64URL_RE.fullmatch(value):
        raise ValueError("invalid_base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid_base64url") from exc


def _base64url_no_padding(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _raw_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _claim_string(raw: object) -> str:
    return raw if isinstance(raw, str) else ""


def _audience_string(raw: object) -> str:
    if isinstance(raw, str) and raw != "":
        return raw
    if isinstance(raw, list) and len(raw) > 0:
        return _claim_string(raw[0])
    return ""


def _numeric_unix(raw: object) -> int | None:
    if not isinstance(raw, int) or isinstance(raw, bool) or raw <= 0:
        return None
    return raw


def _timestamp(value: datetime) -> float:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc).timestamp()
    return value.astimezone(timezone.utc).timestamp()
