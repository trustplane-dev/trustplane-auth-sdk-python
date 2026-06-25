#!/bin/sh
set -eu

if git grep -n -E '/Users/|medhams|tii\.ae|digitaloceantoken|gitlab-personal|github-personal|BEGIN (RSA|OPENSSH|EC|PRIVATE) KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN' -- . ':!.git' ':!LICENSE' ':!scripts/scan-leaks.sh'; then
  echo "leak scan failed"
  exit 1
fi
