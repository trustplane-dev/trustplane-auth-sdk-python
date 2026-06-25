#!/bin/sh
set -eu

wheel_path="${1:-}"
if [ -z "$wheel_path" ]; then
  wheel_path="$(find dist -name '*.whl' -type f | sort | tail -n 1)"
fi

python_bin="${PYTHON:-python}"
if ! command -v "$python_bin" >/dev/null 2>&1; then
  python_bin="python3"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

"$python_bin" -m venv "$tmpdir/venv"
"$tmpdir/venv/bin/python" -m pip install -U pip >/dev/null
"$tmpdir/venv/bin/python" -m pip install "$wheel_path" >/dev/null
"$tmpdir/venv/bin/python" - <<'PY'
from trustplane_auth import body_sha256, build_request, sign_request

assert body_sha256(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
assert callable(build_request)
assert callable(sign_request)
PY
