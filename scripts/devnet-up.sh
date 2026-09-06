#!/bin/sh
# Start the VEILNET devnet (nodeA/B/C + test-server + dero-mock). DEV ONLY.
# Usage: bash scripts/devnet-up.sh
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

if [ "${MAINNET:-0}" = "1" ] || [ "${VEILNET_MAINNET:-0}" = "1" ]; then
  echo "FATAL: mainnet env set — refusing to start devnet near mainnet." >&2
  exit 1
fi
for a in "$@"; do
  case "$a" in *mainnet*|*Mainnet*|*MAINNET*)
    echo "FATAL: mainnet argument refused in devnet script: $a" >&2; exit 1;;
  esac
done

mkdir -p .veilnet-dev/nodeA .veilnet-dev/nodeB .veilnet-dev/nodeC .veilnet-dev/dero-mock
export VEILNET_NETWORK=devnet
docker compose -f deploy/docker-compose.yml up -d --build

deadline=$(( $(date +%s) + 90 ))
for url in http://127.0.0.1:18080/health http://127.0.0.1:18091/health; do
  while ! curl -fsS --max-time 3 "$url" >/dev/null 2>&1; do
    if [ "$(date +%s)" -gt "$deadline" ]; then
      echo "devnet health timeout: $url" >&2; exit 1
    fi
    sleep 2
  done
done

cat <<'EOF'

VEILNET devnet is up (DEVNET ONLY — never mainnet).
Export these fixtures, then run the integration suite:

  export VEILNET_DEVNET_SERVER="http://127.0.0.1:18080"
  export VEILNET_TUNNEL_PROXY="http://127.0.0.1:18101"  # via nodeA when implemented
  export VEILNET_TUNNEL_DNS="http://127.0.0.1:18080"    # stub /dns on test-server
  export VEILNET_NODE_CTL="http://127.0.0.1:18101"
  go test ./tests/integration/ -v

Without the tunnel fixtures the integration tests SKIP as
"unverified" — that is honest, never a pass.
EOF
