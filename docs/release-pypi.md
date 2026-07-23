# PyPI SDK release runbook

## Release contract

- PyPI project: `trustplane-auth-sdk`
- Release tag: `v0.2.2`
- Package version: `0.2.2`

The release tag must be an annotated, GPG-signed tag made by `Medh Mesh <maintainer@trustplane.dev>` with fingerprint `6F46FDF8F73DDBAAAF5DEBA1FAB81A8805C362CA`. It must target the exact current `main` commit and `pyproject.toml` must already contain the mapped PEP 440 version.

`.github/workflows/release-pypi.yml` verifies that signed tag with the checked-in public key, runs the test and wheel smoke checks, and publishes the exact tagged build. It never creates commits or tags.

## One-time PyPI configuration

Configure PyPI Trusted Publishing for:

- project: `trustplane-auth-sdk`
- owner/repository: `trustplane-dev/trustplane-auth-sdk-python`
- workflow: `release-pypi.yml`
- branch: `main`
- environment: blank, unless a protected release environment is deliberately introduced

The workflow uses `id-token: write` and `pypa/gh-action-pypi-publish`; it does not accept a long-lived PyPI token.

## Release procedure

1. Include the intended stable package version in a reviewed, signed change and merge it to `main` after checks pass.
2. From that exact `main` commit, create, verify, and push the signed tag:

   ```sh
   git tag -s v0.2.2 -m "TrustPlane Auth Python SDK v0.2.2"
   git tag -v v0.2.2
   git push origin v0.2.2
   ```

3. Dispatch `release-pypi.yml` from `main` with `version=v0.2.2` and `publish_package=false` to run release readiness.
4. After the successful readiness run, dispatch it again with `publish_package=true`.
5. Verify `python -m pip install trustplane-auth-sdk==0.2.2` in a clean environment before updating public docs.

Never overwrite a PyPI version or release tag. Correct a published package in a new semver release.
