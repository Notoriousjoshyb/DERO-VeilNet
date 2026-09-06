#!/bin/sh
# Stop the VEILNET devnet. `bash scripts/devnet-down.sh --wipe` also removes dev state.
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
docker compose -f deploy/docker-compose.yml down
if [ "${1:-}" = "--wipe" ]; then
  rm -rf .veilnet-dev
  echo "Devnet stopped; .veilnet-dev wiped."
else
  echo "Devnet stopped; dev state kept in .veilnet-dev (pass --wipe to remove)."
fi
