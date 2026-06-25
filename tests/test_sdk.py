from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trustplane_auth import (
    DEFAULT_AUTHORIZATION_TYPE,
    DEFAULT_TIME_BUCKET_SECONDS,
    HEADER_AUTHORIZATION,
    HEADER_BODY_SHA256,
    HEADER_NONCE,
    HEADER_PROOF,
    HEADER_TRANSCRIPT_SHA256,
    SOFTWARE_KEY_BINDING,
    RequestInput,
    body_sha256,
    build_request,
    sign_request,
)

CONFORMANCE_DIR = Path("testdata/conformance/v1")


def test_build_request_matches_transcript_v1_conformance_vectors() -> None:
    for name in ["transcript-v1.json", "transcript-v1.ambiguous-query-headers.json"]:
        fixture = read_json(name)
        material = build_request(request_input_from_fixture(fixture))

        assert material.transcript_sha256 == fixture["canonical"]["sha256"]
        assert material.body_sha256 == fixture["transcript"]["body_sha256"]
        assert list(material.canonical_lines) == fixture["canonical"]["lines"]


def test_body_sha256_matches_conformance_vectors() -> None:
    fixture = read_json("body-sha256-v1.json")

    for vector in fixture["vectors"]:
        assert body_sha256(vector["bytes_utf8"].encode("utf-8")) == vector["sha256"]


def test_build_request_rejects_invalid_query_percent_encoding() -> None:
    fixture = read_json("transcript-v1.json")
    request = {
        **request_input_from_fixture(fixture).__dict__,
        "raw_query": "ok=1&bad=%zz",
    }

    with pytest.raises(ValueError, match="invalid_query_percent_encoding"):
        build_request(request)


def test_sign_request_builds_adapter_ready_headers_and_verifiable_proof() -> None:
    fixture = read_json("transcript-v1.json")
    private_key = fixed_key()
    public_key = raw_public_key(private_key)
    request = software_request_input_from_fixture(fixture)
    token = fixture_token_with_cnf(fixture, SOFTWARE_KEY_BINDING, public_key)
    material = build_request(request)

    signed = sign_request(
        request=request,
        passport_token=token,
        private_key=private_key,
        key_id="proof-key-1",
        signer_class=SOFTWARE_KEY_BINDING,
    )

    assert signed.headers[HEADER_AUTHORIZATION] == f"{DEFAULT_AUTHORIZATION_TYPE} {token}"
    assert signed.headers[HEADER_TRANSCRIPT_SHA256] == material.transcript_sha256
    assert signed.headers[HEADER_NONCE] == fixture["transcript"]["nonce"]
    assert signed.headers[HEADER_BODY_SHA256] == fixture["transcript"]["body_sha256"]
    assert signed.headers[HEADER_PROOF]
    assert signed.key_id == "proof-key-1"
    assert signed.signer_class == SOFTWARE_KEY_BINDING

    digest = bytes.fromhex(signed.transcript_sha256)
    signature = decode_base64url(signed.headers[HEADER_PROOF])
    private_key.public_key().verify(signature, digest)


def test_sign_request_supports_pem_private_key_material() -> None:
    fixture = read_json("transcript-v1.json")
    private_key = fixed_key()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = fixture_token_with_cnf(fixture, SOFTWARE_KEY_BINDING, raw_public_key(private_key))

    signed = sign_request(
        request=software_request_input_from_fixture(fixture),
        passport_token=token,
        private_key=pem,
    )

    assert signed.headers[HEADER_PROOF]


def test_sign_request_derives_passport_bound_fields_without_repairing_conflicts() -> None:
    fixture = read_json("transcript-v1.ambiguous-query-headers.json")
    private_key = fixed_key()
    want_request = software_request_input_from_fixture(fixture)
    want = build_request(want_request)
    request = {
        **want_request.__dict__,
        "audience": "",
        "passport_jti": "",
        "issued_at_unix": 0,
        "key_binding": "",
    }

    signed = sign_request(
        request=request,
        passport_token=fixture_token_with_cnf(
            fixture,
            SOFTWARE_KEY_BINDING,
            raw_public_key(private_key),
        ),
        private_key=private_key,
    )

    assert signed.transcript_sha256 == want.transcript_sha256


@pytest.mark.parametrize(
    ("name", "token_factory", "want"),
    [
        (
            "missing audience",
            lambda f, p, _o: fixture_token_with_claims(f, SOFTWARE_KEY_BINDING, p, {"aud": ""}),
            "passport_missing_aud",
        ),
        (
            "missing jti",
            lambda f, p, _o: fixture_token_with_claims(f, SOFTWARE_KEY_BINDING, p, {"jti": ""}),
            "passport_missing_jti",
        ),
        (
            "missing iat",
            lambda f, p, _o: fixture_token_with_claims(f, SOFTWARE_KEY_BINDING, p, {"iat": None}),
            "passport_missing_iat",
        ),
        (
            "missing kid",
            lambda f, p, _o: fixture_token_with_cnf_raw(
                f,
                SOFTWARE_KEY_BINDING,
                encode_base64url(p),
                {"kid": ""},
            ),
            "passport_missing_cnf_kid",
        ),
        (
            "missing public key",
            lambda f, _p, _o: fixture_token_with_cnf_raw(f, SOFTWARE_KEY_BINDING, ""),
            "passport_missing_cnf_public_key_b64url",
        ),
        (
            "invalid public key encoding",
            lambda f, _p, _o: fixture_token_with_cnf_raw(f, SOFTWARE_KEY_BINDING, "not base64url"),
            "invalid_cnf_public_key_b64url",
        ),
        (
            "wrong public key length",
            lambda f, _p, _o: fixture_token_with_cnf_raw(
                f,
                SOFTWARE_KEY_BINDING,
                encode_base64url(b"short"),
            ),
            "invalid_cnf_public_key_size",
        ),
        (
            "mismatched public key",
            lambda f, _p, o: fixture_token_with_cnf(f, SOFTWARE_KEY_BINDING, o),
            "cnf_public_key_mismatch",
        ),
        (
            "missing key binding",
            lambda f, p, _o: fixture_token_with_cnf_raw(f, "", encode_base64url(p)),
            "passport_missing_cnf_key_binding",
        ),
        (
            "non canonical software binding",
            lambda f, p, _o: fixture_token_with_cnf(f, "Software", p),
            "local_raw_key_supports_only_software_key_binding",
        ),
        (
            "hardware local binding",
            lambda f, p, _o: fixture_token_with_cnf(f, "hardware_local", p),
            "local_raw_key_supports_only_software_key_binding",
        ),
        (
            "attested workload binding",
            lambda f, p, _o: fixture_token_with_cnf(f, "attested_workload", p),
            "local_raw_key_supports_only_software_key_binding",
        ),
        (
            "remote kms binding",
            lambda f, p, _o: fixture_token_with_cnf(f, "remote_kms", p),
            "local_raw_key_supports_only_software_key_binding",
        ),
    ],
)
def test_sign_request_rejects_passport_binding_failures(
    name: str,
    token_factory: Any,
    want: str,
) -> None:
    fixture = read_json("transcript-v1.json")
    private_key = fixed_key()
    public_key = raw_public_key(private_key)
    other_public_key = raw_public_key(other_fixed_key())

    with pytest.raises(ValueError, match=want):
        sign_request(
            request=software_request_input_from_fixture(fixture),
            passport_token=token_factory(fixture, public_key, other_public_key),
            private_key=private_key,
        )


@pytest.mark.parametrize(
    ("name", "request_patch", "proof_patch", "want"),
    [
        ("audience conflict", {"audience": "other-api"}, {}, "passport_audience_mismatch"),
        ("jti conflict", {"passport_jti": "other-jti"}, {}, "passport_jti_mismatch"),
        ("iat conflict", {"issued_at_unix": 1740000001}, {}, "passport_iat_mismatch"),
        ("kid conflict", {}, {"key_id": "other-kid"}, "passport_cnf_kid_mismatch"),
        (
            "request key binding conflict",
            {"key_binding": "hardware_local"},
            {},
            "local_raw_key_supports_only_software_key_binding",
        ),
        (
            "signer class conflict",
            {},
            {"signer_class": "attested_workload"},
            "local_raw_key_supports_only_software_key_binding",
        ),
    ],
)
def test_sign_request_rejects_caller_field_conflicts(
    name: str,
    request_patch: dict[str, Any],
    proof_patch: dict[str, str],
    want: str,
) -> None:
    fixture = read_json("transcript-v1.json")
    private_key = fixed_key()
    public_key = raw_public_key(private_key)
    request = {**software_request_input_from_fixture(fixture).__dict__, **request_patch}
    proof_kwargs = {"key_id": "proof-key-1", **proof_patch}

    with pytest.raises(ValueError, match=want):
        sign_request(
            request=request,
            passport_token=fixture_token_with_cnf(fixture, SOFTWARE_KEY_BINDING, public_key),
            private_key=private_key,
            **proof_kwargs,
        )


def test_request_binding_changes_affect_transcript_and_proof() -> None:
    fixture = read_json("transcript-v1.json")
    private_key = fixed_key()
    token = fixture_token_with_cnf(fixture, SOFTWARE_KEY_BINDING, raw_public_key(private_key))
    base = software_request_input_from_fixture(fixture)
    changed = {
        **base.__dict__,
        "nonce": "nonce-v1-002",
        "headers": [
            {"name": "Content-Type", "value": "application/json"},
            {"name": "X-TrustPlane-Nonce", "value": "nonce-v1-002"},
        ],
    }

    one = sign_request(request=base, passport_token=token, private_key=private_key)
    two = sign_request(request=changed, passport_token=token, private_key=private_key)

    assert two.transcript_sha256 != one.transcript_sha256
    assert two.headers[HEADER_PROOF] != one.headers[HEADER_PROOF]
    assert two.canonical_lines != one.canonical_lines


def test_missing_inputs_return_clear_errors() -> None:
    with pytest.raises(ValueError, match="missing_"):
        build_request()
    with pytest.raises(ValueError, match="missing_passport_token"):
        sign_request(request={}, passport_token="", private_key=fixed_key())
    with pytest.raises(ValueError, match="missing_private_key"):
        sign_request(request={}, passport_token="header.payload.signature")


def test_signature_rejects_wrong_digest() -> None:
    fixture = read_json("transcript-v1.json")
    private_key = fixed_key()
    signed = sign_request(
        request=software_request_input_from_fixture(fixture),
        passport_token=fixture_token_with_cnf(
            fixture,
            SOFTWARE_KEY_BINDING,
            raw_public_key(private_key),
        ),
        private_key=private_key,
    )

    with pytest.raises(InvalidSignature):
        private_key.public_key().verify(
            decode_base64url(signed.headers[HEADER_PROOF]),
            b"\x00" * 32,
        )


def request_input_from_fixture(fixture: dict[str, Any]) -> RequestInput:
    transcript = fixture["transcript"]
    return RequestInput(
        method=transcript["method"],
        scheme=transcript["scheme"],
        authority=transcript["authority"],
        path=transcript["path"],
        raw_query=fixture["raw_request"]["query"],
        audience=transcript["audience"],
        route_id=transcript["route_id"],
        content_encoding=transcript["content_encoding"],
        body=fixture["raw_request"]["body_utf8"].encode("utf-8"),
        headers=fixture["raw_request"]["headers"],
        header_allow_list=transcript["headers"]["allow_list"],
        passport_jti=transcript["passport_jti"],
        nonce=transcript["nonce"],
        issued_at_unix=transcript["issued_at"],
        key_binding=transcript["key_binding"],
        time_bucket_seconds=DEFAULT_TIME_BUCKET_SECONDS,
    )


def software_request_input_from_fixture(fixture: dict[str, Any]) -> RequestInput:
    base = request_input_from_fixture(fixture)
    return RequestInput(**{**base.__dict__, "key_binding": SOFTWARE_KEY_BINDING})


def read_json(name: str) -> dict[str, Any]:
    return json.loads((CONFORMANCE_DIR / name).read_text(encoding="utf-8"))


def fixed_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        bytes(
            [
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                25,
                26,
                27,
                28,
                29,
                30,
                31,
            ]
        )
    )


def other_fixed_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        bytes(
            [
                31,
                30,
                29,
                28,
                27,
                26,
                25,
                24,
                23,
                22,
                21,
                20,
                19,
                18,
                17,
                16,
                15,
                14,
                13,
                12,
                11,
                10,
                9,
                8,
                7,
                6,
                5,
                4,
                3,
                2,
                1,
                0,
            ]
        )
    )


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fixture_token_with_cnf(fixture: dict[str, Any], key_binding: str, public_key: bytes) -> str:
    return fixture_token_with_cnf_raw(fixture, key_binding, encode_base64url(public_key))


def fixture_token_with_cnf_raw(
    fixture: dict[str, Any],
    key_binding: str,
    public_key_b64url: str,
    cnf_override: dict[str, Any] | None = None,
) -> str:
    cnf: dict[str, Any] = {"kid": "proof-key-1"}
    if key_binding != "":
        cnf["key_binding"] = key_binding
    if public_key_b64url != "":
        cnf["public_key_b64url"] = public_key_b64url
    for key, value in (cnf_override or {}).items():
        if value is None:
            cnf.pop(key, None)
        else:
            cnf[key] = value
    return fixture_token_with_claims(fixture, key_binding, None, {"cnf": cnf})


def fixture_token_with_claims(
    fixture: dict[str, Any],
    key_binding: str,
    public_key: bytes | None,
    overrides: dict[str, Any],
) -> str:
    cnf: dict[str, Any] = {"kid": "proof-key-1"}
    if key_binding != "":
        cnf["key_binding"] = key_binding
    if public_key is not None:
        cnf["public_key_b64url"] = encode_base64url(public_key)

    payload: dict[str, Any] = {
        "aud": fixture["transcript"]["audience"],
        "iat": fixture["transcript"]["issued_at"],
        "jti": fixture["transcript"]["passport_jti"],
        "cnf": cnf,
    }
    for key, value in overrides.items():
        if value is None:
            payload.pop(key, None)
        else:
            payload[key] = value

    return f"{encode_jwt_part({'alg': 'EdDSA', 'typ': 'JWT'})}.{encode_jwt_part(payload)}.signature"


def encode_jwt_part(value: dict[str, Any]) -> str:
    return encode_base64url(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_base64url(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)
