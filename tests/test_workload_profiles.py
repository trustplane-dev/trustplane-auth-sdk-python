from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from trustplane_auth import (
    HTTPResponse,
    WorkloadProfileClient,
    WorkloadProfileError,
    WorkloadProfileOptions,
    workload_profile_pop_transcript,
)

FIXTURE = Path("testdata/workload-profile-resolution-v1/golden-transcript.json")
POLICY = "policy://tenant/orders"
KEY_ID = "ta-key-orders"
NOW = 1_760_000_001


def test_workload_profile_transcript_matches_cross_language_golden_fixture() -> None:
    fixture = json.loads(FIXTURE.read_text())
    transcript = workload_profile_pop_transcript(
        fixture["challenge_id"],
        fixture["nonce"],
        fixture["issued_at_unix"],
        fixture["expires_at_unix"],
        fixture["policy_ref"],
        fixture["key_id"],
    )

    assert _b64url(transcript) == fixture["transcript_b64url"]
    assert (
        f"sha256:{hashlib.sha256(fixture['policy_ref'].encode()).hexdigest()}"
        == fixture["policy_fingerprint_sha256"]
    )
    Ed25519PublicKey.from_public_bytes(_decode(fixture["public_key_b64url"])).verify(
        _decode(fixture["signature_b64url"]), transcript
    )


def test_resolve_signs_server_challenge_validates_response_and_caches() -> None:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    calls: list[str] = []

    def transport(
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HTTPResponse:
        assert method == "POST"
        assert headers == {"Accept": "application/json", "Content-Type": "application/json"}
        assert timeout > 0
        path = url.split(".test", 1)[1]
        calls.append(path)
        request = json.loads(body or b"{}")
        if path == "/v1/public/workload-profiles/challenges":
            assert request == {"enrollment_policy_ref": POLICY, "key_id": KEY_ID}
            return _response(
                201,
                {
                    "transcript_version": "trustplane-workload-profile-resolution-pop-v1",
                    "challenge_id": "wpr-challenge-1",
                    "nonce": "nonce-1",
                    "issued_at_unix": NOW - 1,
                    "expires_at_unix": NOW + 120,
                },
            )
        assert path == "/v1/public/workload-profiles/resolve"
        assert set(request) == {
            "enrollment_policy_ref",
            "key_id",
            "challenge_id",
            "nonce",
            "issued_at_unix",
            "expires_at_unix",
            "pop_signature_b64url",
        }
        assert request["enrollment_policy_ref"] == POLICY
        assert request["key_id"] == KEY_ID
        key.public_key().verify(
            _decode(request["pop_signature_b64url"]),
            workload_profile_pop_transcript(
                "wpr-challenge-1", "nonce-1", NOW - 1, NOW + 120, POLICY, KEY_ID
            ),
        )
        return _response(200, _active_response())

    client = WorkloadProfileClient(transport, now_unix=lambda: NOW)
    options = _options(key)
    first = client.resolve(options)
    second = client.resolve(options)

    assert calls == [
        "/v1/public/workload-profiles/challenges",
        "/v1/public/workload-profiles/resolve",
    ]
    assert first is second
    profile = first.select_profile("GET", "/api/customers")
    assert profile.auth_base_url == "https://auth.example.test"
    assert first.select_signing_profile("GET", "/api/customers").route_id == "route-customers"
    with pytest.raises(WorkloadProfileError, match="no_matching_profile"):
        first.select_profile("GET", "/api/admin")


def test_pending_is_not_cached_and_must_match_retry_after_header() -> None:
    key = Ed25519PrivateKey.generate()
    calls = 0

    def transport(
        _method: str,
        url: str,
        _headers: dict[str, str],
        _body: bytes | None,
        _timeout: float,
    ) -> HTTPResponse:
        nonlocal calls
        calls += 1
        if url.endswith("/challenges"):
            return _response(201, _challenge())
        return _response(
            200,
            _stable_response("pending", retry_after_seconds=15),
            {"Retry-After": "15"},
        )

    client = WorkloadProfileClient(transport, now_unix=lambda: NOW)
    first = client.resolve(_options(key))
    assert first.state == "pending"
    assert first.retry_after_seconds == 15
    with pytest.raises(WorkloadProfileError, match="workload_profile_pending") as error:
        first.select_profile("GET", "/api/customers")
    assert error.value.retry_after == 15
    assert client.resolve(_options(key)).state == "pending"
    assert calls == 4


@pytest.mark.parametrize(
    ("mutate", "want"),
    [
        (lambda value: value.update({"key_id": "another-key"}), "binding_mismatch"),
        (
            lambda value: value["profiles"][0].update({"private_upstream_url": "https://private"}),
            "malformed_workload_profile_response",
        ),
        (
            lambda value: value["profiles"][0].update({"route_match_type": "Template"}),
            "malformed_workload_profile_response",
        ),
        (
            lambda value: value.update({"key_expires_at_unix": NOW - 1}),
            "malformed_workload_profile_response",
        ),
        (
            lambda value: value.update({"refresh_at_unix": NOW - 1}),
            "malformed_workload_profile_response",
        ),
        (
            lambda value: value["profiles"][0].update({"refresh_at_unix": NOW - 1}),
            "malformed_workload_profile_response",
        ),
    ],
)
def test_resolve_rejects_misbinding_and_non_schema_public_fields(mutate: Any, want: str) -> None:
    key = Ed25519PrivateKey.generate()
    active = _active_response()
    mutate(active)

    def transport(
        _method: str,
        url: str,
        _headers: dict[str, str],
        _body: bytes | None,
        _timeout: float,
    ) -> HTTPResponse:
        if url.endswith("/challenges"):
            return _response(201, _challenge())
        return _response(200, active)

    with pytest.raises(WorkloadProfileError, match=want):
        WorkloadProfileClient(transport, now_unix=lambda: NOW).resolve(_options(key))


def test_active_response_with_stale_refresh_boundary_is_rejected() -> None:
    key = Ed25519PrivateKey.generate()
    active = _active_response()
    active["refresh_at_unix"] = NOW - 1
    calls = 0

    def transport(
        _method: str,
        url: str,
        _headers: dict[str, str],
        _body: bytes | None,
        _timeout: float,
    ) -> HTTPResponse:
        nonlocal calls
        calls += 1
        if url.endswith("/challenges"):
            return _response(201, _challenge())
        return _response(200, active)

    client = WorkloadProfileClient(transport, now_unix=lambda: NOW)
    with pytest.raises(WorkloadProfileError, match="malformed_workload_profile_response"):
        client.resolve(_options(key))
    assert calls == 2


@pytest.mark.parametrize("field", ["key_expires_at_unix", "refresh_at_unix"])
def test_pending_rejects_stale_key_or_refresh_boundary(field: str) -> None:
    key = Ed25519PrivateKey.generate()
    pending = _stable_response("pending", retry_after_seconds=15)
    pending[field] = NOW - 1

    def transport(
        _method: str,
        url: str,
        _headers: dict[str, str],
        _body: bytes | None,
        _timeout: float,
    ) -> HTTPResponse:
        if url.endswith("/challenges"):
            return _response(201, _challenge())
        return _response(200, pending, {"Retry-After": "15"})

    with pytest.raises(WorkloadProfileError, match="malformed_workload_profile_response"):
        WorkloadProfileClient(transport, now_unix=lambda: NOW).resolve(_options(key))


def test_selection_rejects_ambiguous_or_unsafe_concrete_path() -> None:
    key = Ed25519PrivateKey.generate()
    active = _active_response()
    alternate = dict(active["profiles"][0])
    alternate["profile_id"] = "wpr:sha256:zzzz"
    active["profiles"].append(alternate)

    def transport(
        _method: str,
        url: str,
        _headers: dict[str, str],
        _body: bytes | None,
        _timeout: float,
    ) -> HTTPResponse:
        if url.endswith("/challenges"):
            return _response(201, _challenge())
        return _response(200, active)

    resolution = WorkloadProfileClient(transport, now_unix=lambda: NOW).resolve(_options(key))
    with pytest.raises(WorkloadProfileError, match="ambiguous_profile"):
        resolution.select_profile("GET", "/api/customers")
    with pytest.raises(WorkloadProfileError, match="unsafe_request_path"):
        resolution.select_profile("GET", "/api/customers?include=orders")


def _options(key: Ed25519PrivateKey) -> WorkloadProfileOptions:
    return WorkloadProfileOptions(
        control_url="https://control.example.test",
        enrollment_policy_ref=POLICY,
        key_id=KEY_ID,
        private_key=key,
    )


def _challenge() -> dict[str, object]:
    return {
        "transcript_version": "trustplane-workload-profile-resolution-pop-v1",
        "challenge_id": "wpr-challenge-1",
        "nonce": "nonce-1",
        "issued_at_unix": NOW - 1,
        "expires_at_unix": NOW + 120,
    }


def _active_response() -> dict[str, object]:
    value = _stable_response("active")
    value["profiles"] = [
        {
            "profile_id": "wpr:sha256:customers",
            "profile_version": "workload-signing-profile-v1",
            "auth_base_url": "https://auth.example.test",
            "key_id": KEY_ID,
            "subject": "workload:orders",
            "issuer": "https://issuer.example.test",
            "trust_domain": "example.test",
            "audience": "orders-api",
            "canonical_route_id": "route-customers",
            "method": "GET",
            "route_match_type": "Exact",
            "route_path": "/api/customers",
            "acknowledged_target_configuration_version": 7,
            "expires_at_unix": NOW + 180,
            "refresh_at_unix": NOW + 60,
        }
    ]
    return value


def _stable_response(
    state: str,
    *,
    retry_after_seconds: int | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "state": state,
        "policy_fingerprint_sha256": f"sha256:{hashlib.sha256(POLICY.encode()).hexdigest()}",
        "key_id": KEY_ID,
        "key_expires_at_unix": NOW + 300,
        "refresh_at_unix": NOW + 60,
        "profiles": [],
    }
    if retry_after_seconds is not None:
        result["retry_after_seconds"] = retry_after_seconds
    return result


def _response(
    status: int,
    value: object,
    headers: dict[str, str] | None = None,
) -> HTTPResponse:
    return HTTPResponse(
        status,
        {"Content-Type": "application/json", "Cache-Control": "no-store", **(headers or {})},
        json.dumps(value).encode(),
    )


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")
