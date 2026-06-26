# PyPI Release Runbook

This runbook covers release readiness for the TrustPlane Auth Python SDK package.

## Package

- PyPI project: `trustplane-auth-sdk`
- GitHub owner: `trustplane-dev`
- GitHub repository: `trustplane-auth-sdk-python`
- Workflow filename: `release-pypi.yml`
- Release branch: `main`
- PyPI Trusted Publishing environment: blank unless the release policy intentionally adds one

The repository keeps `pyproject.toml` at version `0.0.0` until the manual release workflow prepares a versioned release.

## Version Mapping

TrustPlane release tags use a leading `v` and prerelease tags use `-rc.N`. Python package versions must follow PEP 440, so release candidates use `rcN`.

- TrustPlane tag: `v0.1.0-rc.1`
- Python package version: `0.1.0rc1`

Stable releases map without the leading `v`:

- TrustPlane tag: `v0.1.0`
- Python package version: `0.1.0`

The release workflow accepts only:

```text
^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$
```

## Release Workflow

The manual workflow is `.github/workflows/release-pypi.yml`.

It runs only through `workflow_dispatch` and rejects dispatches from any branch other than `main`.

Inputs:

- `version`: required TrustPlane release version such as `v0.1.0-rc.1`
- `publish_package`: boolean, default `false`

Default behavior is dry-run release readiness:

- `publish_package=false`
- no git commit
- no tag
- no PyPI publish
- no GitHub Release

The workflow verifies that the git tag does not already exist and that the mapped PyPI version does not already exist before it updates `pyproject.toml`, rewrites the README install command for the exact package version, builds the sdist and wheel, and runs the clean wheel install/import smoke.

## Trusted Publishing Setup

Before setting `publish_package=true`, configure PyPI Trusted Publishing for:

- PyPI project: `trustplane-auth-sdk`
- GitHub owner: `trustplane-dev`
- GitHub repository: `trustplane-auth-sdk-python`
- Workflow filename: `release-pypi.yml`
- Branch: `main`
- Environment: blank unless we intentionally add one

The workflow grants `id-token: write` and publishes through `pypa/gh-action-pypi-publish`. Do not add or use a long-lived PyPI token for normal releases.

PyPI project creation may require a pending trusted publisher configuration before the first publish. If PyPI rejects the first publish because the project or trusted publisher is not configured, fix the PyPI Trusted Publishing settings and rerun only if the version still does not exist on PyPI.

## Dry-Run Mode

Run the workflow from `main` with:

- `version=v0.1.0-rc.1`
- `publish_package=false`

Dry-run mode validates the version, checks that the tag and PyPI version are unused, updates `pyproject.toml` and README release metadata inside the workflow job, builds the artifacts, runs the test suite and scans, and smoke-tests the built wheel. It does not commit, tag, publish to PyPI, or create a GitHub Release.

## Publish Failure Model

The workflow publishes to PyPI before it commits the version bump, creates the annotated tag, or pushes `main`. PyPI is the irreversible step.

If publish fails before PyPI upload:

1. There should be no release commit on `main`.
2. There should be no pushed tag.
3. Fix the package metadata, build contents, or PyPI Trusted Publishing configuration.
4. Rerun with the same version only if the mapped PyPI version still does not exist.

If PyPI publish succeeds but the later git push fails:

1. Do not republish or overwrite the PyPI version.
2. Do not delete, move, or recreate the PyPI artifact.
3. Repair the version commit and annotated tag publication from the same workflow commit and exact package version.
4. If the tag was created in the failed workflow job but not pushed, recreate the same annotated tag on the same release commit with `Medh Mesh <maintainer@trustplane.dev>` and push it.

If package contents are wrong after a successful PyPI publish, advance to a new prerelease version such as `v0.1.0-rc.2`.

## GitHub Releases

This workflow does not create a GitHub Release. Treat GitHub Release creation as a follow-up only if it becomes established repository policy.

## Adoption Readiness

TP-056 live SDK smoke is required before calling the SDK adoption-ready. A PyPI dry run or package publish by itself is release mechanics, not end-to-end adoption proof.
