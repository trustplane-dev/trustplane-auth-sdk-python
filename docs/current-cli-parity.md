# Current caller parity

| Capability | SDK API |
| --- | --- |
| Generate/import/export local software key | `generate_local_ed25519_key`, `private_key_from_base64url`, `export_local_ed25519_key` |
| Issue short-lived local passport | `issue_passport` |
| Canonical body/query/header transcript | `build_request` |
| Raw passport-bound proof | `sign_request` |
| Active key-grant profile validation | `SigningProfile.from_control` |
| Route-safe signed HTTP request | `ProtectedClient.prepare`, `ProtectedClient.request` |
| Public TA-G1 auto-enrollment protocol | `EnrollmentClient.enroll` plus an application proof callback |
| JWT, AWS IID, Azure IMDS proof values | enrollment proof helpers |
| Broker IPC v1 caller | `build_broker_request`, `BrokerClient.issue`, `broker_headers` |

Operator-only verification, bundle authoring/signing, runtime startup, and deployment commands are deliberately excluded because they are not caller SDK operations.

Provider credential acquisition is injected because Kubernetes, CI, SPIFFE, and cloud identity libraries differ by host environment. The SDK validates the server-bound requirement and owns challenge, PoP, submission, retry, bounded response handling, capability polling, and activation status normalization.
