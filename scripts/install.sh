#!/usr/bin/env bash
# Installs VeilNet binaries + OS service files (Linux/macOS).
#
#   sudo ./scripts/install.sh              # system-wide: /usr/local/bin + systemd unit
#   ./scripts/install.sh --user            # current user only (systemd --user / ~/Library/LaunchAgents)
#   ./scripts/install.sh --build           # build first via scripts/build.sh
#   ./scripts/install.sh --no-service      # binaries only, no service registration
#   ./scripts/install.sh --prefix /opt/veilnet [--bindir ...] [--unitdir ...]
#
# Idempotent: re-running overwrites the same files and re-enables the units.
# Binaries keep running across restarts once the service is enabled.
set -euo pipefail
cd "$(dirname "$0")/.."

PREFIX="${PREFIX:-/usr/local}"
BINDIR=""
UNITDIR=""
DO_BUILD=0
DO_SERVICE=1
USER_MODE=0
DO_START=0

while [ $# -gt 0 ]; do
  case "$1" in
    --user) USER_MODE=1; shift ;;
    --build) DO_BUILD=1; shift ;;
    --no-service) DO_SERVICE=0; shift ;;
    --start) DO_START=1; shift ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --bindir) BINDIR="$2"; shift 2 ;;
    --unitdir) UNITDIR="$2"; shift 2 ;;
    --help|-h) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown flag: $1 (see --help)" >&2; exit 2 ;;
  esac
done

if [ "$DO_BUILD" = "1" ]; then
  ./scripts/build.sh
fi

for b in veilnet veilnet-node veilnet-service; do
  if [ ! -x "dist/$b" ]; then
    echo "Missing dist/$b. Re-run with --build (or ./scripts/build.sh first)." >&2
    exit 1
  fi
done

OS="$(uname -s)"
if [ -z "$BINDIR" ]; then
  if [ "$USER_MODE" = "1" ]; then BINDIR="$HOME/.local/bin"; else BINDIR="$PREFIX/bin"; fi
fi

echo "Installing binaries to $BINDIR ..."
mkdir -p "$BINDIR"
install -m 0755 dist/veilnet "$BINDIR/veilnet"
install -m 0755 dist/veilnet-node "$BINDIR/veilnet-node"
install -m 0755 dist/veilnet-service "$BINDIR/veilnet-service"
if [ -f dist/VERSION ]; then install -m 0644 dist/VERSION "$BINDIR/veilnet-VERSION"; fi
case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) echo "Note: $BINDIR is not in PATH. Add: export PATH=\"$BINDIR:\$PATH\"" ;;
esac

if [ "$DO_SERVICE" = "0" ]; then
  echo 'Binaries installed (--no-service: no service registered).'
  exit 0
fi

PKG="deploy/packaging"

if [ "$OS" = "Darwin" ]; then
  if [ "$USER_MODE" = "1" ]; then LAUNCH_DIR="$HOME/Library/LaunchAgents"; else LAUNCH_DIR="/Library/LaunchDaemons"; fi
  if [ -z "$UNITDIR" ]; then UNITDIR="$LAUNCH_DIR"; fi
  echo "Installing launchd plists to $UNITDIR ..."
  mkdir -p "$UNITDIR"
  sed "s#/usr/local/bin/veilnet#$BINDIR/veilnet#g" "$PKG/com.veilnet.service.plist" > "$UNITDIR/com.veilnet.service.plist"
  sed "s#/usr/local/bin/veilnet#$BINDIR/veilnet#g" "$PKG/com.veilnet.node.plist" > "$UNITDIR/com.veilnet.node.plist"
  chmod 0644 "$UNITDIR/com.veilnet.service.plist" "$UNITDIR/com.veilnet.node.plist"
  if [ "$USER_MODE" = "1" ]; then
    echo "Loaded for current user only. Start with:"
    echo "  launchctl bootstrap gui/$(id -u) $UNITDIR/com.veilnet.service.plist"
  else
    echo "Installed system-wide. Start with (needs root):"
    echo "  sudo launchctl bootstrap system $UNITDIR/com.veilnet.service.plist"
  fi
  if [ "$DO_START" = "1" ]; then
    if [ "$USER_MODE" = "1" ]; then
      launchctl bootstrap "gui/$(id -u)" "$UNITDIR/com.veilnet.service.plist" 2>/dev/null || true
    else
      sudo launchctl bootstrap system "$UNITDIR/com.veilnet.service.plist"
    fi
  fi
  echo 'Done. The node unit (com.veilnet.node.plist) is installed but not started; start it on node machines only.'
  exit 0
fi

# --- Linux ---
if command -v systemctl >/dev/null 2>&1; then
  if [ "$USER_MODE" = "1" ]; then
    if [ -z "$UNITDIR" ]; then UNITDIR="$HOME/.config/systemd/user"; fi
    SYSTEMD_ARGS="--user"
  else
    if [ -z "$UNITDIR" ]; then UNITDIR="/etc/systemd/system"; fi
    SYSTEMD_ARGS=""
  fi
  echo "Installing systemd units to $UNITDIR ..."
  mkdir -p "$UNITDIR"
  # shellcheck disable=SC2086
  sed "s#/usr/local/bin/veilnet#$BINDIR/veilnet#g" "$PKG/veilnet.service" > "$UNITDIR/veilnet.service"
  sed "s#/usr/local/bin/veilnet#$BINDIR/veilnet#g" "$PKG/veilnet-node.service" > "$UNITDIR/veilnet-node.service"
  chmod 0644 "$UNITDIR/veilnet.service" "$UNITDIR/veilnet-node.service"
  # shellcheck disable=SC2086
  systemctl $SYSTEMD_ARGS daemon-reload
  # shellcheck disable=SC2086
  systemctl $SYSTEMD_ARGS enable veilnet.service
  echo 'Enabled veilnet.service (starts on boot). The node unit is installed but not enabled; enable it on node machines:'
  # shellcheck disable=SC2086
  echo "  systemctl $SYSTEMD_ARGS enable --now veilnet-node.service"
  if [ "$DO_START" = "1" ]; then
    # shellcheck disable=SC2086
    systemctl $SYSTEMD_ARGS start veilnet.service
    echo 'Started veilnet.service.'
  else
    # shellcheck disable=SC2086
    echo "Start now with: systemctl $SYSTEMD_ARGS start veilnet.service"
  fi
  exit 0
fi

if command -v rc-service >/dev/null 2>&1; then
  cat <<EOF
OpenRC detected (no systemd unit installed).
Binaries are in $BINDIR. To supervise veilnet-service under OpenRC, create
/etc/init.d/veilnet-service (example):

  #!/sbin/openrc-run
  name="veilnet-service"
  command="$BINDIR/veilnet-service"
  command_background="yes"
  pidfile="/run/veilnet-service.pid"

then:  sudo chmod +x /etc/init.d/veilnet-service
       sudo rc-update add veilnet-service default
       sudo rc-service veilnet-service start
EOF
  exit 0
fi

echo "Binaries installed to $BINDIR; no supported init system found, so no service was registered."
echo 'Run veilnet-service directly, or install systemd/launchd/OpenRC integration manually.'
