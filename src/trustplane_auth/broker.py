from __future__ import annotations

import hashlib
import json
import re
import secrets
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .profile import validate_concrete_request_path
from .transcript import (
    HEADER_AUTHORIZATION,
    HEADER_BODY_SHA256,
    HEADER_NONCE,
    HEADER_PROOF,
    HEADER_TRANSCRIPT_SHA256,
    QUERY_NORMALIZATION_RFC3986,
    SOFTWARE_KEY_BINDING,
    Header,
    RequestInput,
    body_sha256,
    normalize_query_rfc3986_sort_keys_values,
)

BROKER_IPC_V1_VERSION = "trustplane-broker-ipc-v1"
BROKER_IPC_V1_KIND = "broker_ipc_exchange"
BROKER_PROTOCOL = "local-json-ipc"
BROKER_OPERATION_ISSUE = "issue_request_bound_passport"


@dataclass(frozen=True)
class BrokerRequestInput:
    request: RequestInput
    request_id: str = ""
    context: Mapping[str, str] | None = None
    selected_context_fields: Sequence[str] = ()
    requested_key_binding: str = SOFTWARE_KEY_BINDING
    acceptable_key_bindings: Sequence[str] = ()
    allow_software_fallback: bool = False


@dataclass(frozen=True)
class PreparedBrokerRequest:
    request: dict[str, Any]
    raw_headers: Mapping[str, str]


@dataclass(frozen=True)
class BrokerResponse:
    request_id: str
    accepted: bool
    status: str
    reason_code: str
    issued_at: int
    expires_at: int
    artifacts: Mapping[str, Any] | None
    error: Mapping[str, Any] | None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> BrokerResponse:
        return cls(
            request_id=_text(raw.get("request_id")),
            accepted=raw.get("accepted") is True,
            status=_text(raw.get("status")),
            reason_code=_text(raw.get("reason_code")),
            issued_at=_integer(raw.get("issued_at")),
            expires_at=_integer(raw.get("expires_at")),
            artifacts=raw.get("artifacts") if isinstance(raw.get("artifacts"), Mapping) else None,
            error=raw.get("error") if isinstance(raw.get("error"), Mapping) else None,
        )


def build_broker_request(input_: BrokerRequestInput) -> PreparedBrokerRequest:
    source = input_.request
    validate_concrete_request_path(source.path.strip())
    nonce = source.nonce.strip() or secrets.token_hex(16)
    request_id = input_.request_id.strip() or f"broker-client-{secrets.token_hex(8)}"
    raw_query = source.raw_query.strip().lstrip("?")
    normalized = normalize_query_rfc3986_sort_keys_values(raw_query)
    raw_headers: dict[str, str] = {}
    for header in source.headers:
        item = _header(header)
        raw_headers[item.name.strip().lower()] = item.value.strip()
    raw_headers[HEADER_NONCE.lower()] = nonce
    allow_list = _canonical_names(source.header_allow_list or tuple(raw_headers))
    selected: list[dict[str, str]] = []
    for name in allow_list:
        if name not in raw_headers:
            raise ValueError(f"covered_header_missing: {name}")
        selected.append({"name": name, "value_sha256": _sha256(raw_headers[name])})
    context = dict(input_.context or {})
    selected_context = (
        list(input_.selected_context_fields) if input_.selected_context_fields else sorted(context)
    )
    requested = input_.requested_key_binding.strip() or SOFTWARE_KEY_BINDING
    acceptable = list(input_.acceptable_key_bindings) or [requested]
    source_body = source.body.encode("utf-8") if isinstance(source.body, str) else source.body
    http_request: dict[str, Any] = {
        "method": source.method.strip().upper(),
        "scheme": source.scheme.strip().lower(),
        "authority": source.authority.strip().lower(),
        "path": source.path.strip(),
        "content_encoding": source.content_encoding.strip().lower() or "identity",
        "query": {
            "raw": raw_query,
            "normalization": QUERY_NORMALIZATION_RFC3986,
            "normalized": normalized,
            "sha256": _sha256(normalized),
        },
        "headers": {"allow_list": allow_list, "selected": selected},
        "audience": source.audience.strip(),
        "route_id": source.route_id.strip(),
        "body_sha256": source.body_sha256.strip() or body_sha256(source_body),
        "nonce": nonce,
    }
    request: dict[str, Any] = {
        "request_id": request_id,
        "protocol": BROKER_PROTOCOL,
        "operation": BROKER_OPERATION_ISSUE,
        "http": http_request,
        "ctx": {"selected_fields": selected_context, "values": context},
        "key_binding": {
            "intent": "route_policy_minimum",
            "requested_key_binding": requested,
            "acceptable_key_bindings": acceptable,
            "allow_software_fallback": input_.allow_software_fallback,
        },
    }
    for name in ("method", "scheme", "authority", "path", "audience", "route_id", "nonce"):
        if http_request[name] == "":
            raise ValueError(f"missing_{name}")
    return PreparedBrokerRequest(request, raw_headers)


def broker_headers(prepared: PreparedBrokerRequest, response: BrokerResponse) -> dict[str, str]:
    if not response.accepted or response.artifacts is None:
        raise ValueError("broker_response_not_accepted")
    passport = response.artifacts.get("passport")
    stamp = response.artifacts.get("stamp")
    if not isinstance(passport, Mapping) or not isinstance(stamp, Mapping):
        raise ValueError("broker_response_invalid")
    if (
        _text(passport.get("format")) != "compact-jws"
        or not _text(passport.get("value"))
        or not _text(passport.get("jti"))
        or _text(stamp.get("format")) != "ed25519-transcript-v1"
        or not _text(stamp.get("value"))
        or re.fullmatch(r"[0-9a-f]{64}", _text(stamp.get("transcript_sha256"))) is None
    ):
        raise ValueError("broker_response_invalid")
    headers = {
        name: value
        for name, value in prepared.raw_headers.items()
        if name.lower() != HEADER_NONCE.lower() and value.strip()
    }
    http = prepared.request["http"]
    headers.update(
        {
            HEADER_AUTHORIZATION: f"Bearer {_text(passport.get('value'))}",
            HEADER_PROOF: _text(stamp.get("value")),
            HEADER_TRANSCRIPT_SHA256: _text(stamp.get("transcript_sha256")),
            HEADER_NONCE: _text(http.get("nonce")),
            HEADER_BODY_SHA256: _text(http.get("body_sha256")),
        }
    )
    return headers


class BrokerClient:
    def __init__(self, socket_path: str, *, timeout: float = 30.0) -> None:
        self.socket_path = socket_path
        self.timeout = timeout

    def issue(self, prepared: PreparedBrokerRequest) -> BrokerResponse:
        if not self.socket_path.strip():
            raise ValueError("missing_socket_path")
        envelope = {
            "version": BROKER_IPC_V1_VERSION,
            "kind": BROKER_IPC_V1_KIND,
            "request": prepared.request,
        }
        raw = json.dumps(envelope, separators=(",", ":")).encode() + b"\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout)
            connection.connect(self.socket_path)
            connection.sendall(raw)
            response_raw = bytearray()
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                response_raw.extend(chunk)
                if len(response_raw) > 1 << 20:
                    raise ValueError("broker_response_too_large")
                if b"\n" in chunk:
                    break
        try:
            decoded = json.loads(response_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("broker_response_invalid") from exc
        if not isinstance(decoded, dict):
            raise ValueError("broker_response_invalid")
        response = BrokerResponse.from_dict(decoded)
        if response.request_id != prepared.request["request_id"]:
            raise ValueError("broker_response_request_id_mismatch")
        return response


def _header(value: object) -> Header:
    if isinstance(value, Header):
        return value
    if isinstance(value, Mapping):
        return Header(_text(value.get("name")), _text(value.get("value")))
    if isinstance(value, tuple) and len(value) == 2:
        return Header(str(value[0]), str(value[1]))
    raise ValueError("invalid_header")


def _canonical_names(values: Sequence[str]) -> list[str]:
    return sorted({str(value).strip().lower() for value in values if str(value).strip()})


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _integer(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
