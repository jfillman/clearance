#!/usr/bin/env bash
# Fails unless this machine is linux/ARCH (amd64 or arm64), so a CI leg that says it tests an architecture cannot
# silently run on another one (a runner label that moved, or a matrix typo).
#
#   tools/runner-arch.sh ARCH
set -euo pipefail
want="${1:?usage: tools/runner-arch.sh amd64|arm64}"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) got=amd64;;
  Linux-aarch64 | Linux-arm64) got=arm64;;
  *) got="$(uname -s)-$(uname -m)";;
esac
if [ "$got" != "$want" ]; then
  echo "::error::this runner is $got, the job tests $want"
  exit 1
fi
echo "runner: linux/$got ($(uname -r))"
