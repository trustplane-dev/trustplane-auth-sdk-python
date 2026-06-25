# TrustPlane Auth Conformance Vectors v1

These public-safe vectors were copied from TrustPlane Auth reference commit `86532eaa6e18569fbfb29a175055c1a2b381839c`.

They are language-neutral contract fixtures for SDKs and client helpers. They are not runtime secrets and do not grant access to any TrustPlane environment.

Consumers must match canonical bytes, SHA-256 digests, signer taxonomy ordering, and bundle source-rule values exactly. Do not reinterpret these fixtures from generated runtime config, host paths, or private environment assumptions.

SDKs must treat these vectors as required tests before claiming compatibility with the covered TrustPlane Auth contracts. The manifest is the entry point for automated runners.

No file in this directory contains live credentials. Any public key material is test-only and not a secret. These fixtures do not include private keys.
