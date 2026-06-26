# TrustPlane Auth SDK for Python

Preview Python caller SDK for TrustPlane Auth request signing.

This package provides caller-side helpers for:

- building `transcript-v1` request material
- computing body SHA-256 values
- parsing passport claims needed by signing
- raw local Ed25519 software signing
- returning adapter-ready TrustPlane Auth headers

It does not include a verifier, broker, adapter, policy engine, SPIFFE issuer, deployment code, enrollment flow, bundle mutation, or TrustPlane Control API.

## Install

Install released preview versions from PyPI with an exact version pin:

```sh
python -m pip install trustplane-auth-sdk==0.1.0rc1
```

For unreleased local changes, test this repository through a local checkout or built wheel.

## Package Name

The Python distribution name candidate is `trustplane-auth-sdk`.

The import module is `trustplane_auth`:

```python
from trustplane_auth import body_sha256, build_request, sign_request
```

The package version remains `0.0.0` until the release workflow is introduced.

PyPI trusted publishing is planned in a follow-up.

## Build Request Example

```python
from trustplane_auth import SOFTWARE_KEY_BINDING, Header, build_request

material = build_request(
    method="POST",
    scheme="https",
    authority="orders.example",
    path="/v1/orders",
    audience="orders-api",
    route_id="orders.create",
    content_encoding="identity",
    body=b'{"order_id":"ord_123","amount":"42.00"}',
    headers=[
        Header(name="Content-Type", value="application/json"),
        Header(name="X-TrustPlane-Nonce", value="nonce-v1-001"),
    ],
    header_allow_list=["content-type", "x-trustplane-nonce"],
    passport_jti="passport-v1-minimal-001",
    nonce="nonce-v1-001",
    issued_at_unix=1740000000,
    key_binding=SOFTWARE_KEY_BINDING,
)

print(material.transcript_sha256)
```

## Signing Example

Signing requires a real passport whose `cnf.key_binding` is `software` and whose `cnf.public_key_b64url` matches the Ed25519 private key.

```python
from pathlib import Path

from trustplane_auth import Header, sign_request

passport = "header.payload.signature"
private_key_pem = Path("ed25519-private-key.pem").read_bytes()

signed = sign_request(
    request={
        "method": "POST",
        "scheme": "https",
        "authority": "orders.example",
        "path": "/v1/orders",
        "route_id": "orders.create",
        "content_encoding": "identity",
        "body": b'{"order_id":"ord_123","amount":"42.00"}',
        "headers": [
            Header(name="Content-Type", value="application/json"),
            Header(name="X-TrustPlane-Nonce", value="nonce-v1-001"),
        ],
        "header_allow_list": ["content-type", "x-trustplane-nonce"],
        "nonce": "nonce-v1-001",
    },
    passport_token=passport,
    private_key=private_key_pem,
)

headers = signed.headers
```

`sign_request` reads passport-bound fields from the passport and fails if caller-supplied consistency checks conflict. It does not infer or repair `aud`, `jti`, `iat`, `cnf.kid`, `cnf.key_binding`, or `cnf.public_key_b64url` from caller request inputs.

## Conformance Posture

`testdata/conformance/v1` contains public-safe contract vectors copied from the TrustPlane Auth reference. Tests assert exact canonical transcript lines, transcript SHA-256 values, and body SHA-256 values.

## Security Rule

This SDK signs only the verifier-rebuilt request transcript. Raw local signing is software-only and requires an Ed25519 private key whose public key exactly matches the passport `cnf.public_key_b64url` claim.
