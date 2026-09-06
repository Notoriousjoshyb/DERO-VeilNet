#!/bin/sh
# Devnet node entrypoint: hard separation from mainnet.
# Refuses any mainnet flag/env, then execs veilnet-node in devnet mode.
set -eu
for arg in "$@"; do
  case "$arg" in
    *mainnet*|*Mainnet*|*MAINNET*)
      echo "FATAL: mainnet mode refused inside devnet image (arg: $arg)" >&2
      exit 1
      ;;
  esac
done
if [ "${MAINNET:-0}" = "1" ] || [ "${VEILNET_NETWORK:-devnet}" != "devnet" ]; then
  echo "FATAL: devnet image requires VEILNET_NETWORK=devnet" >&2
  exit 1
fi
exec veilnet-node --devnet --data-dir /data "$@"
