from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

HEADER_AUTHORIZATION = "Authorization"
HEADER_BODY_SHA256 = "X-TrustPlane-Body-SHA256"
HEADER_NONCE = "X-TrustPlane-Nonce"
HEADER_PROOF = "X-TrustPlane-Proof"
HEADER_TRANSCRIPT_SHA256 = "X-TrustPlane-Transcript-SHA256"

DEFAULT_AUTHORIZATION_TYPE = "Bearer"

SOFTWARE_KEY_BINDING = "software"
HARDWARE_LOCAL_KEY_BINDING = "hardware_local"
REMOTE_KMS_KEY_BINDING = "remote_kms"
ATTESTED_WORKLOAD_KEY_BINDING = "attested_workload"

TRANSCRIPT_V1_VERSION = "trustplane-transcript-v1"
TRANSCRIPT_V1_KIND = "request_transcript"
TRANSCRIPT_V1_FORMAT = "trustplane-transcript-v1-lines"
QUERY_NORMALIZATION_RFC3986 = "rfc3986-sort-keys-values"
DEFAULT_TIME_BUCKET_SECONDS = 20

_TRANSCRIPT_V1_COVERED_FIELDS = (
    "method",
    "scheme",
    "authority",
    "path",
    "audience",
    "route_id",
    "content_encoding",
    "query_normalization.algorithm",
    "query_normalization.normalized",
    "query_normalization.sha256",
    "query_sha256",
    "headers.allow_list",
    "headers.selected",
    "body_sha256",
    "passport_jti",
    "nonce",
    "issued_at",
    "time_bucket",
    "key_binding",
)


@dataclass(frozen=True)
class Header:
    name: str
    value: str


@dataclass(frozen=True)
class RequestInput:
    method: str = ""
    scheme: str = ""
    authority: str = ""
    path: str = ""
    raw_query: str = ""
    audience: str = ""
    route_id: str = ""
    content_encoding: str = ""
    body: bytes | str = b""
    body_sha256: str = ""
    headers: Sequence[Header | Mapping[str, Any] | tuple[str, str]] = ()
    header_allow_list: Sequence[str] = ()
    nonce: str = ""
    issued_at: datetime | None = None
    issued_at_unix: int = 0
    passport_jti: str = ""
    key_binding: str = ""
    time_bucket_seconds: int = DEFAULT_TIME_BUCKET_SECONDS


@dataclass(frozen=True)
class RequestMaterial:
    transcript_sha256: str
    body_sha256: str
    canonical_lines: tuple[str, ...]


@dataclass(frozen=True)
class _QueryNormalization:
    algorithm: str
    normalized: str
    sha256: str


@dataclass(frozen=True)
class _SelectedHeader:
    name: str
    value_sha256: str


@dataclass(frozen=True)
class _TranscriptHeaders:
    allow_list: tuple[str, ...]
    selected: tuple[_SelectedHeader, ...]


@dataclass(frozen=True)
class _TranscriptV1:
    method: str
    scheme: str
    authority: str
    path: str
    audience: str
    route_id: str
    content_encoding: str
    query_normalization: _QueryNormalization
    query_sha256: str
    headers: _TranscriptHeaders
    body_sha256: str
    passport_jti: str
    nonce: str
    issued_at: int
    time_bucket: int
    key_binding: str
    covered_fields: tuple[str, ...]


def body_sha256(body: bytes) -> str:
    return _sha256_hex_bytes(_body_bytes(body))


def normalize_query_rfc3986_sort_keys_values(raw: str) -> str:
    """Return the exact transcript-v1 normalized query representation."""
    return _normalize_query_rfc3986_sort_keys_values(raw.lstrip("?"))


def build_request(
    request: RequestInput | Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> RequestMaterial:
    request_input = _coerce_request_input(request, kwargs)
    transcript = _build_transcript(request_input)
    canonical_lines = _canonical_lines(transcript)
    return RequestMaterial(
        transcript_sha256=_sha256_hex("\n".join(canonical_lines)),
        body_sha256=transcript.body_sha256,
        canonical_lines=tuple(canonical_lines),
    )


def _build_transcript(input_: RequestInput) -> _TranscriptV1:
    issued_at = input_.issued_at_unix
    if issued_at == 0 and input_.issued_at is not None:
        issued_at = int(_utc_datetime(input_.issued_at).timestamp())

    bucket_seconds = input_.time_bucket_seconds
    if not isinstance(bucket_seconds, int) or bucket_seconds < 0:
        raise ValueError("invalid_time_bucket_seconds")

    body_digest = input_.body_sha256.strip() or body_sha256(_body_bytes(input_.body))
    raw_query = input_.raw_query.strip()
    if raw_query.startswith("?"):
        raw_query = raw_query[1:]
    normalized_query = _normalize_query_rfc3986_sort_keys_values(raw_query)
    query_digest = _sha256_hex(normalized_query)
    allow_list = _canonical_allow_list(input_.header_allow_list)
    selected = _select_headers(input_.headers, allow_list)

    transcript = _TranscriptV1(
        method=input_.method.strip().upper(),
        scheme=input_.scheme.strip().lower(),
        authority=input_.authority.strip().lower(),
        path=input_.path.strip(),
        audience=input_.audience.strip(),
        route_id=input_.route_id.strip(),
        content_encoding=input_.content_encoding.strip().lower() or "identity",
        query_normalization=_QueryNormalization(
            algorithm=QUERY_NORMALIZATION_RFC3986,
            normalized=normalized_query,
            sha256=query_digest,
        ),
        query_sha256=query_digest,
        headers=_TranscriptHeaders(allow_list=allow_list, selected=selected),
        body_sha256=body_digest,
        passport_jti=input_.passport_jti.strip(),
        nonce=input_.nonce.strip(),
        issued_at=issued_at,
        time_bucket=0 if bucket_seconds == 0 else issued_at // bucket_seconds,
        key_binding=input_.key_binding.strip(),
        covered_fields=_TRANSCRIPT_V1_COVERED_FIELDS,
    )
    _validate_transcript(transcript)
    return transcript


def _canonical_lines(transcript: _TranscriptV1) -> list[str]:
    return [
        f"version={TRANSCRIPT_V1_VERSION}",
        f"method={transcript.method}",
        f"scheme={transcript.scheme}",
        f"authority={transcript.authority}",
        f"path={transcript.path}",
        f"audience={transcript.audience}",
        f"route_id={transcript.route_id}",
        f"content_encoding={transcript.content_encoding}",
        f"query_normalization.algorithm={transcript.query_normalization.algorithm}",
        f"query_normalization.normalized={transcript.query_normalization.normalized}",
        f"query_normalization.sha256={transcript.query_normalization.sha256}",
        f"query_sha256={transcript.query_sha256}",
        f"headers.allow_list={','.join(transcript.headers.allow_list)}",
        f"headers.selected={_selected_header_line(transcript.headers.selected)}",
        f"body_sha256={transcript.body_sha256}",
        f"passport_jti={transcript.passport_jti}",
        f"nonce={transcript.nonce}",
        f"issued_at={transcript.issued_at}",
        f"time_bucket={transcript.time_bucket}",
        f"key_binding={transcript.key_binding}",
    ]


def _normalize_query_rfc3986_sort_keys_values(raw: str) -> str:
    if raw == "":
        return ""

    pairs: list[tuple[str, str, int]] = []
    for index, part in enumerate(raw.split("&")):
        key_raw, separator, value_raw = part.partition("=")
        key = _encode_rfc3986(_strict_unquote(key_raw))
        value = _encode_rfc3986(_strict_unquote(value_raw if separator else ""))
        pairs.append((key, value, index))

    pairs.sort(key=lambda pair: (pair[0], pair[1], pair[2]))
    return "&".join(f"{key}={value}" for key, value, _ in pairs)


def _validate_transcript(transcript: _TranscriptV1) -> None:
    required = {
        "method": transcript.method,
        "scheme": transcript.scheme,
        "authority": transcript.authority,
        "path": transcript.path,
        "audience": transcript.audience,
        "route_id": transcript.route_id,
        "content_encoding": transcript.content_encoding,
        "query_normalization.algorithm": transcript.query_normalization.algorithm,
        "query_normalization.sha256": transcript.query_normalization.sha256,
        "query_sha256": transcript.query_sha256,
        "body_sha256": transcript.body_sha256,
        "passport_jti": transcript.passport_jti,
        "nonce": transcript.nonce,
        "key_binding": transcript.key_binding,
    }
    for name, value in required.items():
        if value == "":
            raise ValueError(f"missing_{name.replace('.', '_')}")
    if transcript.issued_at == 0:
        raise ValueError("missing_issued_at")
    if len(transcript.headers.allow_list) != len(transcript.headers.selected):
        raise ValueError("missing_selected_headers")


def _canonical_allow_list(allow_list: Sequence[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for raw_name in allow_list:
        name = str(raw_name).strip().lower()
        if name == "" or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return tuple(sorted(out))


def _select_headers(
    headers: Sequence[Header | Mapping[str, Any] | tuple[str, str]],
    allow_list: Sequence[str],
) -> tuple[_SelectedHeader, ...]:
    raw_by_name: dict[str, str] = {}
    for header in headers:
        name, value = _coerce_header(header)
        name = name.strip().lower()
        if name == "" or name in raw_by_name:
            continue
        raw_by_name[name] = value.strip()

    selected: list[_SelectedHeader] = []
    for allowed in allow_list:
        selected_value = raw_by_name.get(allowed)
        if selected_value is None:
            continue
        selected.append(_SelectedHeader(name=allowed, value_sha256=_sha256_hex(selected_value)))
    return tuple(selected)


def _selected_header_line(headers: Sequence[_SelectedHeader]) -> str:
    return ",".join(f"{header.name}:{header.value_sha256}" for header in headers)


def _encode_rfc3986(value: str) -> str:
    out: list[str] = []
    for byte in value.encode("utf-8"):
        if (
            0x41 <= byte <= 0x5A
            or 0x61 <= byte <= 0x7A
            or 0x30 <= byte <= 0x39
            or byte in (0x2D, 0x2E, 0x5F, 0x7E)
        ):
            out.append(chr(byte))
        else:
            out.append(f"%{byte:02X}")
    return "".join(out)


def _strict_unquote(value: str) -> str:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if index + 2 >= len(value) or not all(
            char in "0123456789ABCDEFabcdef" for char in value[index + 1 : index + 3]
        ):
            raise ValueError("invalid_query_percent_encoding")
        index += 3
    return unquote(value)


def _coerce_request_input(
    request: RequestInput | Mapping[str, Any] | None,
    kwargs: Mapping[str, Any],
) -> RequestInput:
    data: dict[str, Any] = {}
    if request is None:
        data = {}
    elif isinstance(request, RequestInput):
        data = {field.name: getattr(request, field.name) for field in fields(RequestInput)}
    elif is_dataclass(request):
        data = {field.name: getattr(request, field.name) for field in fields(request)}
    else:
        data = dict(request)
    data.update(kwargs)
    return RequestInput(**data)


def _coerce_header(header: Header | Mapping[str, Any] | tuple[str, str]) -> tuple[str, str]:
    if isinstance(header, Header):
        return header.name, header.value
    if isinstance(header, Mapping):
        name = header.get("name", header.get("Name", ""))
        value = header.get("value", header.get("Value", ""))
        return str(name), str(value)
    name, value = header
    return str(name), str(value)


def _body_bytes(body: bytes | str | bytearray | memoryview) -> bytes:
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return bytes(body)


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _sha256_hex(value: str) -> str:
    return _sha256_hex_bytes(value.encode("utf-8"))


def _sha256_hex_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
