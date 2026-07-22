from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trustplane_auth import (
    BrokerRequestInput,
    BrokerResponse,
    EnrollmentClient,
    EnrollmentOptions,
    Header,
    HTTPResponse,
    ProtectedClient,
    RequestInput,
    SigningProfile,
    broker_headers,
    build_broker_request,
    enrollment_pop_transcript,
    export_local_ed25519_key,
    issue_passport,
    jwt_enrollment_proof,
    private_key_from_base64url,
    raw_public_key,
)
from trustplane_auth.passport import PassportOptions


def test_issue_passport_matches_current_cli_shape() -> None:
    key = fixed_key()
    issued = issue_passport(
        PassportOptions(
            issuer="https://issuer.example",
            subject="workload:orders",
            audience="orders-api",
            trust_domain="example",
            key_id="kid-orders",
            private_key=key,
            now=datetime.fromtimestamp(1_750_000_000, timezone.utc),
            jti="jti-test",
        )
    )
    header, payload, signature = issued.token.split(".")
    key.public_key().verify(_decode(signature), f"{header}.{payload}".encode())
    claims = json.loads(_decode(payload))
    assert claims["trust_domain"] == "example"
    assert claims["cnf"]["kid"] == issued.public_key_b64url
    assert claims["cnf"]["key_binding"] == "software"


def test_cli_base64url_private_key_round_trip() -> None:
    exported = export_local_ed25519_key(fixed_key())
    parsed = private_key_from_base64url(exported.private_key_b64url)
    assert raw_public_key(parsed) == raw_public_key(fixed_key())
    assert len(exported.fingerprint_sha256) == 71


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_protected_client_signs_all_http_methods(method: str) -> None:
    client = ProtectedClient(
        profile(method),
        fixed_key(),
        now=lambda: datetime.fromtimestamp(1_750_000_000, timezone.utc),
        random_bytes=lambda size: bytes([len(method)]) * size,
    )
    body = b"" if method in {"GET", "HEAD"} else b'{"ok":true}'
    prepared = client.prepare(
        method,
        "/orders/123?b=2&a=1",
        body,
        {"Content-Type": "application/json"},
    )
    assert prepared.request.method == method
    assert prepared.request.full_url.endswith("/orders/123?b=2&a=1")
    headers = {name.lower(): value for name, value in prepared.request.header_items()}
    for name in (
        "authorization",
        "x-trustplane-body-sha256",
        "x-trustplane-nonce",
        "x-trustplane-proof",
        "x-trustplane-transcript-sha256",
    ):
        assert headers[name]


def test_protected_client_rejects_sibling_prefix() -> None:
    scoped = profile("GET")
    scoped = SigningProfile(
        **{
            **scoped.__dict__,
            "route_match_type": "PathPrefix",
            "route_path": "/api",
        }
    )
    with pytest.raises(ValueError, match="request_outside_signing_profile"):
        ProtectedClient(scoped, fixed_key()).prepare("GET", "/apix")
    for unsafe in ("api/1", "/api/..", "/api/%2Fadmin", "/api/{id}", "/api/"):
        with pytest.raises(ValueError, match="unsafe_request_path"):
            ProtectedClient(scoped, fixed_key()).prepare("GET", unsafe)
    exact = SigningProfile(
        **{**profile("GET").__dict__, "route_path": "/orders", "route_match_type": "Exact"}
    )
    assert (
        ProtectedClient(exact, fixed_key())
        .prepare("GET", "?a=1")
        .request.full_url.endswith("/orders?a=1")
    )


def test_enrollment_completes_challenge_pop_submission_and_activation() -> None:
    key = fixed_key()
    public_key = raw_public_key(key)
    status_reads = 0

    def transport(
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HTTPResponse:
        nonlocal status_reads
        assert timeout > 0
        path = url.split(".test", 1)[1]
        if path == "/v1/public/enrollment/challenges":
            request = json.loads(body or b"{}")
            assert request["enrollment_policy_ref"] == "enrpol_test"
            assert request["public_key_b64url"] == _b64url(public_key)
            return response(
                201,
                {
                    "challenge_id": "challenge-1",
                    "nonce": "nonce-1",
                    "enrollment_policy_ref": "enrpol_test",
                    "source_kind": "kubernetes_service_account_oidc",
                    "source_revision_id": "revision-1",
                    "required_proof_encoding": "jwt_compact",
                    "expected_audience": "control-enroll",
                    "poll_capability": "poll-secret",
                    "expires_at": "2026-07-22T00:00:00Z",
                },
            )
        if path == "/v1/public/enrollment/submissions":
            request = json.loads(body or b"{}")
            assert request["proof"] == "provider.jwt.token"
            assert request["proof_encoding"] == "jwt_compact"
            key.public_key().verify(
                _decode(request["pop_signature_b64url"]),
                enrollment_pop_transcript("challenge-1", "nonce-1", "enrpol_test", public_key),
            )
            return response(
                202,
                {
                    "request_id": "request-1",
                    "status": "pending",
                    "decision_status": "approved",
                    "runtime_activation_status": "publishing",
                },
            )
        if path == "/v1/public/enrollment/status/request-1":
            status_reads += 1
            assert headers["Authorization"] == "Bearer poll-secret"
            return response(
                200,
                {
                    "request_id": "request-1",
                    "status": "active",
                    "decision_status": "approved",
                    "runtime_activation_status": "active",
                    "created_key_id": "key-1",
                    "key_expires_at": "2026-08-22T00:00:00Z",
                    "target_configuration_version": 42,
                },
            )
        return response(404, {"code": "not_found"})

    result = EnrollmentClient(transport, sleep=lambda _: None).enroll(
        EnrollmentOptions(
            control_url="https://control.example.test",
            enrollment_policy_ref="enrpol_test",
            provider="kubernetes_service_account_oidc",
            private_key=key,
            proof_provider=lambda challenge: proof_for(challenge.expected_audience),
            poll_interval=0.001,
            timeout=1.0,
        )
    )
    assert (
        result.status,
        result.decision_status,
        result.runtime_activation_status,
        result.key_id,
        result.target_configuration_version,
        status_reads,
    ) == ("active", "approved", "active", "key-1", 42, 1)
    assert not any(
        secret in json.dumps(result.__dict__)
        for secret in ("poll-secret", "provider.jwt.token", "nonce-1")
    )


def test_broker_builder_binds_request_and_returns_adapter_headers() -> None:
    prepared = build_broker_request(
        BrokerRequestInput(
            request_id="broker-ipc-v1-success-001",
            request=RequestInput(
                method="POST",
                scheme="https",
                authority="orders.example",
                path="/v1/orders",
                raw_query="currency=USD&expand=items",
                audience="orders-api",
                route_id="orders.create",
                content_encoding="identity",
                body_sha256="940a95d372e94ab3e795a0843fc195ad2dd9a161c6e227b0e18fd6d4a92ace93",
                nonce="nonce-broker-ipc-v1-001",
                headers=(Header("content-type", "application/json"),),
                header_allow_list=("content-type", "x-trustplane-nonce"),
            ),
            context={"actor_type": "service", "purpose": "create_order"},
            selected_context_fields=("actor_type", "purpose"),
            requested_key_binding="hardware_local",
            acceptable_key_bindings=("hardware_local", "attested_workload"),
        )
    )
    assert prepared.request["protocol"] == "local-json-ipc"
    assert (
        prepared.request["http"]["query"]["sha256"]
        == "a897301294666a140e3d75a9495b1b312fd0802d5353e911b3edf15ffd081202"
    )
    headers = broker_headers(
        prepared,
        BrokerResponse(
            request_id="broker-ipc-v1-success-001",
            accepted=True,
            status="allow",
            reason_code="broker_passport_issued",
            issued_at=1,
            expires_at=2,
            artifacts={
                "passport": {"format": "compact-jws", "value": "passport", "jti": "jti"},
                "stamp": {
                    "format": "ed25519-transcript-v1",
                    "value": "proof",
                    "transcript_sha256": "a" * 64,
                },
            },
            error=None,
        ),
    )
    assert headers["Authorization"] == "Bearer passport"
    assert headers["X-TrustPlane-Proof"] == "proof"
    assert headers["X-TrustPlane-Nonce"] == "nonce-broker-ipc-v1-001"


def profile(method: str) -> SigningProfile:
    return SigningProfile.from_control(
        {
            "state": "active",
            "reason": "active",
            "key_origin": "trust_anchor_derived",
            "request_base_url": "https://auth.example.test",
            "kid": "kid-1",
            "subject": "workload:1",
            "trust_domain": "example",
            "issuer": "https://issuer.example",
            "route_id": "rt_0123456789abcdef0123456789abcdef",
            "canonical_route_id": "rt_0123456789abcdef0123456789abcdef",
            "route_match_type": "Exact",
            "route_path": "/orders/{id}",
            "method": method,
            "audience": "orders-api",
        }
    )


def proof_for(audience: str):
    assert audience == "control-enroll"
    return jwt_enrollment_proof("provider.jwt.token")


def response(status: int, value: object) -> HTTPResponse:
    return HTTPResponse(status, {"Content-Type": "application/json"}, json.dumps(value).encode())


def fixed_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")
