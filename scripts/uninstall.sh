#!/usr/bin/env bash
# Removes VeilNet binaries + OS service files installed by scripts/install.sh.
#
#   sudo ./scripts/uninstall.sh            # system-wide removal
#   ./scripts/uninstall.sh --user          # remove a --user install
#   ./scripts/uninstall.sh --purge         # ... and delete config/state dirs
#
# Config and state (~/.veilnet, ~/.veilnet-node) are KEPT unless --purge.
set -euo pipefail
cd "$(dirname "$0")/.."

PREFIX="${PREFIX:-/usr/local}"
BINDIR=""
UNITDIR=""
USER_MODE=0
PURGE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_MODE=1; shift ;;
    --purge) PURGE=1; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --bindir) BINDIR="$2"; shift 2 ;;
    --unitdir) UNITDIR="$2"; shift 2 ;;
    --help|-h) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown flag: $1 (see --help)" >&2; exit 2 ;;
  esac
done

if [ -z "$BINDIR" ]; then
  if [ "$USER_MODE" = "1" ]; then BINDIR="$HOME/.local/bin"; else BINDIR="$PREFIX/bin"; fi
fi

OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
  if [ "$USER_MODE" = "1" ]; then LAUNCH_DIR="$HOME/Library/LaunchAgents"; else LAUNCH_DIR="/Library/LaunchDaemons"; fi
  if [ -z "$UNITDIR" ]; then UNITDIR="$LAUNCH_DIR"; fi
  for svc in com.veilnet.service com.veilnet.node; do
    if [ "$USER_MODE" = "1" ]; then
      launchctl bootout "gui/$(id -u)/$svc" 2>/dev/null || true
    else
      sudo launchctl bootout "system/$svc" 2>/dev/null || true
    fi
    rm -f "$UNITDIR/$svc.plist"
    echo "Removed $UNITDIR/$svc.plist"
  done
else
  if command -v systemctl >/dev/null 2>&1; then
    if [ "$USER_MODE" = "1" ]; then
      if [ -z "$UNITDIR" ]; then UNITDIR="$HOME/.config/systemd/user"; fi
      # shellcheck disable=SC2086
      S="systemctl --user"
    else
      if [ -z "$UNITDIR" ]; then UNITDIR="/etc/systemd/system"; fi
      S="systemctl"
    fi
    for svc in veilnet.service veilnet-node.service; do
      # shellcheck disable=SC2086
      $S stop "$svc" 2>/dev/null || true
      # shellcheck disable=SC2086
      $S disable "$svc" 2>/dev/null || true
      rm -f "$UNITDIR/$svc"
      echo "Removed $UNITDIR/$svc"
    done
    # shellcheck disable=SC2086
    $S daemon-reload 2>/dev/null || true
  elif command -v rc-service >/dev/null 2>&1; then
    echo 'OpenRC: if you created /etc/init.d/veilnet-service, remove it now:'
    echo '  sudo rc-service veilnet-service stop; sudo rc-update del veilnet-service default'
    echo '  sudo rm /etc/init.d/veilnet-service'
  fi
fi

for b in veilnet veilnet-node veilnet-service veilnet-VERSION; do
  if [ -e "$BINDIR/$b" ]; then rm -f "$BINDIR/$b"; echo "Removed $BINDIR/$b"; fi
done

if [ "$PURGE" = "1" ]; then
  rm -rf "$HOME/.veilnet" "$HOME/.veilnet-node" "$HOME/.veilnet-dev"
  echo 'Purged ~/.veilnet ~/.veilnet-node ~/.veilnet-dev'
else
  echo 'Kept ~/.veilnet and ~/.veilnet-node (re-run with --purge to delete them).'
fi

echo 'Uninstall complete.'
