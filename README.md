# TrustPlane Auth SDK for Python

Caller-side Python SDK for TrustPlane Auth.

The source API supports CLI-compatible Ed25519 keys and passports, `transcript-v1` signing, active Control key-grant profiles, arbitrary HTTP methods, TA-G1 public auto-enrollment, and broker IPC v1. Published packages can lag source changes; pin a verified release or use a local checkout for unreleased APIs.

## Signed request from a key grant

```python
from trustplane_auth import (
    ProtectedClient,
    SigningProfile,
    private_key_from_base64url,
)

profile = SigningProfile.from_control(control_signing_profile_json)
private_key = private_key_from_base64url(private_key_file_contents.strip())
client = ProtectedClient(profile, private_key)

response = client.request(
    profile.method,
    "/orders/123?expand=items",
    headers={"Accept": "application/json"},
)
```

Each request receives a fresh short-lived passport/JTI, nonce, canonical body/query/header digest, and proof. The client rejects a method or path outside the active profile, including sibling-prefix mistakes. Parameterized profiles require a concrete path (`/orders/123`, not `/orders/{id}`); encoded or ambiguous paths fail closed, query-only targets retain a literal profile path, and redirects are not followed with TrustPlane credentials.

## Auto-enrollment

```python
from trustplane_auth import EnrollmentClient, EnrollmentOptions, jwt_enrollment_proof

result = EnrollmentClient().enroll(
    EnrollmentOptions(
        control_url="https://control.example",
        enrollment_policy_ref="enrpol_...",
        provider="kubernetes_service_account_oidc",
        private_key=private_key,
        proof_provider=lambda challenge: jwt_enrollment_proof(
            obtain_audience_bound_token(challenge.expected_audience)
        ),
    )
)
```

The SDK validates Control's immutable source revision, Azure proof mode when applicable, and required encoding before invoking the proof callback. Helpers also build AWS IID and Azure IMDS attested-document proof values. The safe result never contains proof, key, nonce, signature, or poll capability material. Enrollment requires HTTPS.

Provider credential acquisition stays in the application callback so it can use the host's projected token, CI, SPIFFE, or cloud metadata client. The SDK owns the complete Control protocol. Once a submission is accepted, a polling deadline returns a safe `pending` result with the request ID instead of resubmitting the proof.

## Broker mode

`build_broker_request`, `BrokerClient.issue`, and `broker_headers` provide the caller side of broker IPC v1 over a Unix socket. This package does not include the broker runtime.

## Scope boundary

This package does not embed a verifier, adapter, policy engine, SPIFFE issuer, deployment logic, Control administrative API, or CLI-only bundle/local-demo commands.

Raw local signing is software-only. Stronger signer classes must be fulfilled by an appropriate broker or signer; they are never simulated with an exportable key.
