from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import _b64url, raw_public_key

ENROLLMENT_CHALLENGE_PATH = "/v1/public/enrollment/challenges"
ENROLLMENT_SUBMISSION_PATH = "/v1/public/enrollment/submissions"
ENROLLMENT_STATUS_PATH = "/v1/public/enrollment/status/"
ENROLLMENT_POP_DOMAIN = "trustplane-enrollment-pop-v1"
MAX_ENROLLMENT_RESPONSE_BYTES = 1 << 20


@dataclass(frozen=True)
class EnrollmentChallenge:
    challenge_id: str
    nonce: str
    enrollment_policy_ref: str
    source_kind: str
    source_revision_id: str
    required_proof_encoding: str
    poll_capability: str
    expires_at: str
    proof_mode: str = ""
    expected_audience: str = ""


@dataclass(frozen=True)
class EnrollmentProof:
    encoding: str
    value: object


@dataclass(frozen=True)
class EnrollmentOptions:
    control_url: str
    enrollment_policy_ref: str
    provider: str
    private_key: Ed25519PrivateKey
    proof_provider: Callable[[EnrollmentChallenge], EnrollmentProof]
    wait_for_activation: bool = False
    no_wait_for_activation: bool = False
    poll_interval: float = 2.0
    timeout: float = 300.0
    submit_attempts: int = 2
    client_metadata: Mapping[str, object] | None = None


@dataclass(frozen=True)
class EnrollmentResult:
    request_id: str
    status: str
    decision_status: str
    runtime_activation_status: str
    key_id: str
    key_fingerprint: str
    expires_at: str
    target_configuration_version: int


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class EnrollmentTransport(Protocol):
    def __call__(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HTTPResponse: ...


class EnrollmentError(ValueError):
    def __init__(
        self,
        code: str,
        status_code: int = 0,
        retry_after: float = 0.0,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.retry_after = retry_after


class EnrollmentClient:
    def __init__(
        self,
        transport: EnrollmentTransport | None = None,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._transport = transport or _default_transport
        self._sleep = sleep
        self._monotonic = monotonic

    def enroll(self, options: EnrollmentOptions) -> EnrollmentResult:
        base = _control_url(options.control_url)
        if not _exact(options.enrollment_policy_ref):
            raise EnrollmentError("control_url_and_policy_required")
        provider = options.provider.strip().lower()
        if _expected_proof_encoding(provider) == "" and provider != "azure_instance_identity":
            raise EnrollmentError("unsupported_enrollment_provider")
        if options.timeout <= 0:
            raise EnrollmentError("invalid_enrollment_timeout")
        if options.poll_interval <= 0:
            raise EnrollmentError("invalid_enrollment_poll_interval")
        if options.submit_attempts < 1 or options.submit_attempts > 5:
            raise EnrollmentError("invalid_enrollment_submit_attempts")
        deadline = self._monotonic() + options.timeout
        public_key = raw_public_key(options.private_key)
        challenge_body: dict[str, object] = {
            "enrollment_policy_ref": options.enrollment_policy_ref,
            "public_key_b64url": _b64url(public_key),
        }
        if options.client_metadata is not None:
            challenge_body["client_metadata"] = dict(options.client_metadata)
        challenge = _challenge(
            self._json("POST", base, ENROLLMENT_CHALLENGE_PATH, challenge_body, "", deadline)
        )
        _validate_challenge(challenge, options.enrollment_policy_ref, provider)
        proof = options.proof_provider(challenge)
        if proof.encoding != challenge.required_proof_encoding or proof.value is None:
            raise EnrollmentError("enrollment_required_proof_encoding_mismatch")
        submission = {
            "challenge_id": challenge.challenge_id,
            "nonce": challenge.nonce,
            "proof": proof.value,
            "proof_encoding": proof.encoding,
            "pop_signature_b64url": _b64url(
                options.private_key.sign(
                    enrollment_pop_transcript(
                        challenge.challenge_id,
                        challenge.nonce,
                        options.enrollment_policy_ref,
                        public_key,
                    )
                )
            ),
        }
        status: dict[str, object] | None = None
        for attempt in range(options.submit_attempts):
            try:
                status = self._json(
                    "POST", base, ENROLLMENT_SUBMISSION_PATH, submission, "", deadline
                )
                break
            except EnrollmentError as exc:
                if exc.code not in {"control_unavailable", "control_transient_failure"}:
                    raise
                if attempt + 1 == options.submit_attempts:
                    raise
                self._wait((attempt + 1) * 0.1, deadline)
        if status is None:
            raise EnrollmentError("control_unavailable")
        status = _normalize_status(status)
        request_id = _first(status.get("request_id"), status.get("id"))
        if request_id == "":
            raise EnrollmentError("malformed_enrollment_submission")
        should_wait = options.wait_for_activation or not options.no_wait_for_activation
        if should_wait and not _terminal(status):
            try:
                status = self._poll(
                    base,
                    request_id,
                    challenge.poll_capability,
                    options.poll_interval,
                    deadline,
                )
            except EnrollmentError as exc:
                if exc.code != "enrollment_timeout":
                    raise
                status = {
                    "request_id": request_id,
                    "status": "pending",
                    "runtime_activation_status": "pending",
                }
        result = _result(request_id, status, public_key)
        if _failed(result):
            raise EnrollmentError(result.status)
        return result

    def _poll(
        self,
        base: str,
        request_id: str,
        capability: str,
        interval: float,
        deadline: float,
    ) -> dict[str, object]:
        attempt = 0
        while True:
            try:
                status = _normalize_status(
                    self._json(
                        "GET",
                        base,
                        f"{ENROLLMENT_STATUS_PATH}{quote(request_id, safe='')}",
                        None,
                        capability,
                        deadline,
                    )
                )
                if _terminal(status):
                    return status
                attempt = 0
                delay = interval
            except EnrollmentError as exc:
                if exc.status_code != 429:
                    raise
                delay = max(min(interval * (2**attempt), 30.0), exc.retry_after)
                attempt += 1
            self._wait(delay, deadline)

    def _json(
        self,
        method: str,
        base: str,
        path: str,
        value: object | None,
        capability: str,
        deadline: float,
    ) -> dict[str, object]:
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise EnrollmentError("enrollment_timeout")
        body = None if value is None else json.dumps(value, separators=(",", ":")).encode()
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if capability:
            headers["Authorization"] = f"Bearer {capability}"
        try:
            response = self._transport(method, _endpoint(base, path), headers, body, remaining)
        except TimeoutError as exc:
            raise EnrollmentError("enrollment_timeout") from exc
        except OSError as exc:
            raise EnrollmentError("control_unavailable") from exc
        if len(response.body) > MAX_ENROLLMENT_RESPONSE_BYTES:
            raise EnrollmentError("control_response_invalid")
        if not 200 <= response.status < 300:
            if response.status == 429:
                raise EnrollmentError(
                    "enrollment_status_poll_throttled",
                    429,
                    _retry_after(_header(response.headers, "Retry-After")),
                )
            if response.status >= 500:
                raise EnrollmentError("control_transient_failure", response.status)
            raise EnrollmentError(_safe_remote_code(response.body), response.status)
        try:
            decoded = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EnrollmentError("control_response_invalid") from exc
        if not isinstance(decoded, dict):
            raise EnrollmentError("control_response_invalid")
        return decoded

    def _wait(self, delay: float, deadline: float) -> None:
        if self._monotonic() + delay > deadline:
            raise EnrollmentError("enrollment_timeout")
        self._sleep(delay)


def jwt_enrollment_proof(token: str) -> EnrollmentProof:
    return EnrollmentProof("jwt_compact", token.strip())


def aws_iid_enrollment_proof(document: bytes, signature: bytes) -> EnrollmentProof:
    return EnrollmentProof(
        "aws_iid_base64",
        {
            "document_b64": base64.b64encode(document).decode(),
            "signature_b64": base64.b64encode(signature).decode(),
        },
    )


def azure_imds_enrollment_proof(
    pkcs7: bytes,
    compute_metadata: Mapping[str, object],
) -> EnrollmentProof:
    return EnrollmentProof(
        "azure_imds_attested_document_base64",
        {
            "pkcs7_b64": base64.b64encode(pkcs7).decode(),
            "compute_metadata": dict(compute_metadata),
        },
    )


def enrollment_pop_transcript(
    challenge_id: str,
    nonce: str,
    policy_ref: str,
    public_key: bytes,
) -> bytes:
    return (
        f"{ENROLLMENT_POP_DOMAIN}\n{challenge_id}\n{nonce}\n{policy_ref}\n{_b64url(public_key)}\n"
    ).encode()


def _challenge(raw: Mapping[str, object]) -> EnrollmentChallenge:
    return EnrollmentChallenge(
        challenge_id=_first(raw.get("challenge_id")),
        nonce=_first(raw.get("nonce")),
        enrollment_policy_ref=_first(raw.get("enrollment_policy_ref")),
        source_kind=_first(raw.get("source_kind")),
        source_revision_id=_first(raw.get("source_revision_id")),
        required_proof_encoding=_first(raw.get("required_proof_encoding")),
        poll_capability=_first(raw.get("poll_capability")),
        expires_at=_first(raw.get("expires_at")),
        proof_mode=_first(raw.get("proof_mode")),
        expected_audience=_first(raw.get("expected_audience")),
    )


def _validate_challenge(
    challenge: EnrollmentChallenge,
    policy: str,
    provider: str,
) -> None:
    for value in (
        challenge.challenge_id,
        challenge.nonce,
        challenge.enrollment_policy_ref,
        challenge.source_kind,
        challenge.source_revision_id,
        challenge.required_proof_encoding,
        challenge.poll_capability,
    ):
        if not _exact(value):
            raise EnrollmentError("malformed_enrollment_challenge")
    if challenge.enrollment_policy_ref != policy or challenge.source_kind != provider:
        raise EnrollmentError("enrollment_provider_source_mismatch")
    if provider == "azure_instance_identity":
        if challenge.proof_mode == "managed_identity_jwt":
            if challenge.required_proof_encoding != "jwt_compact" or not _exact(
                challenge.expected_audience
            ):
                raise EnrollmentError("malformed_enrollment_challenge")
        elif challenge.proof_mode == "imds_attested_document":
            if (
                challenge.required_proof_encoding != "azure_imds_attested_document_base64"
                or challenge.expected_audience
            ):
                raise EnrollmentError("malformed_enrollment_challenge")
        else:
            raise EnrollmentError("unsupported_azure_proof_mode")
    elif challenge.proof_mode or challenge.required_proof_encoding != _expected_proof_encoding(
        provider
    ):
        raise EnrollmentError("enrollment_required_proof_encoding_mismatch")


def _expected_proof_encoding(provider: str) -> str:
    if provider in {
        "oidc_jwks",
        "ci_oidc",
        "spiffe",
        "kubernetes_service_account_oidc",
        "gcp_instance_identity",
    }:
        return "jwt_compact"
    return "aws_iid_base64" if provider == "aws_ec2_iid" else ""


def _normalize_status(raw: Mapping[str, object]) -> dict[str, object]:
    status = dict(raw)
    status["status"] = _first(raw.get("status"), raw.get("state")).lower()
    status["decision_status"] = _first(raw.get("decision_status")).lower()
    status["runtime_activation_status"] = _first(
        raw.get("runtime_activation_status"), raw.get("activation_status")
    ).lower()
    if status["runtime_activation_status"] == "active":
        status["status"] = "active"
    elif status["runtime_activation_status"] == "awaiting_manual_distribution":
        status["status"] = "awaiting_manual_distribution"
    elif not status["status"]:
        status["status"] = _first(status["decision_status"], "pending")
    return status


def _terminal(status: Mapping[str, object]) -> bool:
    return (
        _first(status.get("runtime_activation_status"))
        in {
            "active",
            "awaiting_manual_distribution",
            "failed",
        }
        or _first(status.get("status"))
        in {
            "active",
            "awaiting_manual_distribution",
            "failed",
            "denied",
            "rejected",
            "expired",
            "cancelled",
        }
        or _first(status.get("decision_status")) == "rejected"
    )


def _result(request_id: str, status: Mapping[str, object], public_key: bytes) -> EnrollmentResult:
    normalized = _normalize_status(status)
    version = normalized.get("target_configuration_version")
    return EnrollmentResult(
        request_id=request_id,
        status=_first(normalized.get("status"), "pending"),
        decision_status=_first(normalized.get("decision_status")),
        runtime_activation_status=_first(normalized.get("runtime_activation_status")),
        key_id=_first(normalized.get("created_key_id")),
        key_fingerprint=_first(normalized.get("key_fingerprint"))
        or f"sha256:{hashlib.sha256(public_key).hexdigest()}",
        expires_at=_first(normalized.get("key_expires_at")),
        target_configuration_version=version if isinstance(version, int) else 0,
    )


def _failed(result: EnrollmentResult) -> bool:
    return any(
        value in {"failed", "denied", "rejected", "expired", "cancelled"}
        for value in (
            result.status,
            result.decision_status,
            result.runtime_activation_status,
        )
    )


def _control_url(raw: str) -> str:
    parsed = urlparse(raw.strip())
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise EnrollmentError("invalid_control_url")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def _endpoint(base: str, path: str) -> str:
    parsed = urlparse(base)
    return urlunparse(
        (parsed.scheme, parsed.netloc, f"{parsed.path.rstrip('/')}{path}", "", "", "")
    )


def _safe_remote_code(raw: bytes) -> str:
    try:
        decoded = json.loads(raw)
        if isinstance(decoded, dict):
            for value in (decoded.get("code"), decoded.get("error")):
                if isinstance(value, str) and re.fullmatch(r"[a-z0-9_-]{1,96}", value):
                    return value
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    return "control_enrollment_failed"


def _retry_after(value: str) -> float:
    try:
        seconds = int(value)
        return float(min(max(seconds, 0), 86_400))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value).astimezone(timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError):
        return 0.0


def _header(headers: Mapping[str, str], wanted: str) -> str:
    for name, value in headers.items():
        if name.lower() == wanted.lower():
            return value
    return ""


def _first(*values: object) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _exact(value: str) -> bool:
    return bool(value) and value == value.strip()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _default_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: float,
) -> HTTPResponse:
    request = Request(url, data=body, headers=dict(headers), method=method)
    try:
        response = build_opener(_NoRedirect()).open(request, timeout=timeout)
        with response:
            return HTTPResponse(
                response.status,
                dict(response.headers.items()),
                response.read(MAX_ENROLLMENT_RESPONSE_BYTES + 1),
            )
    except HTTPError as exc:
        return HTTPResponse(
            exc.code,
            dict(exc.headers.items()),
            exc.read(MAX_ENROLLMENT_RESPONSE_BYTES + 1),
        )
    except URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError from exc
        raise OSError from exc
