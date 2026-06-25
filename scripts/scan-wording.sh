#!/bin/sh
set -eu

if git grep -n -i -E 'open[- ]source|source is public|generally available|production ready|available on pypi|released now|latest tag' -- . ':!.git' ':!scripts/scan-wording.sh'; then
  echo "premature wording scan failed"
  exit 1
fi
