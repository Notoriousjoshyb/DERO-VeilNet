#!/usr/bin/env bash
# Builds the VeilNet binaries into dist/ (Linux/macOS).
#
# Reproducible-build contract:
#   VERSION defaults to `git describe --tags --always --dirty`, falling back
#   to 0.1.0-dev when git is unavailable. Override with VERSION=1.2.3.
#   SOURCE_DATE_EPOCH defaults to the last commit timestamp (`git log -1
#   --format=%ct`), else the current time. Override for byte-identical
#   rebuilds: SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) ./scripts/build.sh
# The stamped values land in dist/VERSION and dist/BUILDINFO; Go is invoked
# with -trimpath -buildvcs=false so output does not embed absolute paths.
set -euo pipefail
cd "$(dirname "$0")/.."

export GOTOOLCHAIN=local
mkdir -p dist

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)}"
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || date +%s)"
fi
export SOURCE_DATE_EPOCH

GOFLAGS="-trimpath" go build -buildvcs=false -o dist/veilnet ./cmd/veilnet
GOFLAGS="-trimpath" go build -buildvcs=false -o dist/veilnet-node ./cmd/veilnet-node
GOFLAGS="-trimpath" go build -buildvcs=false -o dist/veilnet-service ./cmd/veilnet-service

printf '%s\n' "$VERSION" > dist/VERSION
{
  echo "version=$VERSION"
  echo "source_date_epoch=$SOURCE_DATE_EPOCH"
  echo "go=$(go version | awk '{print $3}')"
} > dist/BUILDINFO

echo "Built: dist/veilnet dist/veilnet-node dist/veilnet-service ($VERSION, epoch $SOURCE_DATE_EPOCH)"
