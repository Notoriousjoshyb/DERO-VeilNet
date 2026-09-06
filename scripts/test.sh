#!/usr/bin/env bash
# Runs VeilNet tests, scoped to a package pattern (default ./internal/...).
# Each agent runs scoped checks inside its own dirs; repo-wide suites are
# the main agent's job at the end.
set -euo pipefail
cd "$(dirname "$0")/.."

export GOTOOLCHAIN=local
go test "${1:-./internal/...}"
