#!/usr/bin/env bash
# VeilNet dev setup for Linux and macOS.
#
# Default (no flags): verify Go >= 1.22, populate the module cache
# (idempotent), report missing OS packages with the exact install command.
#
#   ./scripts/setup.sh                 # check + go mod download (safe default)
#   ./scripts/setup.sh --check         # prerequisite check only (onboarding hook)
#   ./scripts/setup.sh --dry-run       # print install commands, change nothing
#   ./scripts/setup.sh --install       # install missing OS packages (needs root)
#   ./scripts/setup.sh --install --yes # ... without the confirmation prompt
#
# Sourcing contract (used by deploy/packaging/tests/test_detect.sh):
#   source ./scripts/setup.sh
#   veilnet_detect_distro [os-release-file]
#   veilnet_detect_pkg_manager
# then inspect $VEILNET_DISTRO_ID / $VEILNET_PKG_MANAGER and call
#   veilnet_packages_for "$VEILNET_PKG_MANAGER"
# Sourcing must not execute anything; execution happens in main() below.
set -euo pipefail

# --- library state (defaults; safe when sourced) ---------------------------
VEILNET_DISTRO_ID="${VEILNET_DISTRO_ID:-}"
VEILNET_DISTRO_LIKE="${VEILNET_DISTRO_LIKE:-}"
VEILNET_DISTRO_VERSION="${VEILNET_DISTRO_VERSION:-}"
VEILNET_DISTRO_NAME="${VEILNET_DISTRO_NAME:-}"
VEILNET_PKG_MANAGER="${VEILNET_PKG_MANAGER:-}"
VEILNET_GO_MIN_MAJOR=1
VEILNET_GO_MIN_MINOR=22

# veilnet_os_release_file: path to the os-release file in use.
veilnet_os_release_file() {
  printf '%s' "${VEILNET_OS_RELEASE:-/etc/os-release}"
}

# veilnet_detect_distro [path]: parse an os-release file into VEILNET_DISTRO_*.
# Always succeeds; unknown distros yield VEILNET_DISTRO_ID="unknown".
# On macOS (no os-release file) the ID is "macos".
veilnet_detect_distro() {
  local f="${1:-$(veilnet_os_release_file)}"
  local id="" like="" version="" name=""
  if [ -f "$f" ]; then
    id="$(sed -n 's/^ID=//p' "$f" | head -n 1 | tr -d '"'"'" | tr '[:upper:]' '[:lower:]' | xargs || true)"
    like="$(sed -n 's/^ID_LIKE=//p' "$f" | head -n 1 | tr -d '"'"'" | tr '[:upper:]' '[:lower:]' | xargs || true)"
    version="$(sed -n 's/^VERSION_ID=//p' "$f" | head -n 1 | tr -d '"'"'" | xargs || true)"
    name="$(sed -n 's/^NAME=//p' "$f" | head -n 1 | tr -d '"'"'" | xargs || true)"
  elif [ "$(uname -s 2>/dev/null || echo unknown)" = "Darwin" ]; then
    id="macos"
    name="macOS"
    version="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
  fi
  VEILNET_DISTRO_ID="${id:-unknown}"
  VEILNET_DISTRO_LIKE="$like"
  VEILNET_DISTRO_VERSION="${version:-unknown}"
  VEILNET_DISTRO_NAME="${name:-$VEILNET_DISTRO_ID}"
  # Normalize common derivatives to their family via ID_LIKE.
  case "$VEILNET_DISTRO_ID" in
    linuxmint|pop|elementary|zorin|kali|raspbian) VEILNET_DISTRO_ID="ubuntu" ;;
    manjaro|endeavouros|garuda) VEILNET_DISTRO_ID="arch" ;;
  esac
  printf '%s' "$VEILNET_DISTRO_ID"
}

# veilnet_detect_pkg_manager: pick apt/dnf/yum/pacman/zypper/apk/brew/none.
# Honors $VEILNET_PKG_MANAGER as an explicit override. Prefers dnf over yum
# when both are present. Prints the manager name and always succeeds.
veilnet_detect_pkg_manager() {
  if [ -n "${VEILNET_PKG_MANAGER:-}" ]; then
    printf '%s' "$VEILNET_PKG_MANAGER"
    return 0
  fi
  local m="none"
  if [ "$(uname -s 2>/dev/null || echo unknown)" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then m="brew"; else m="brew-missing"; fi
  elif command -v apt-get >/dev/null 2>&1; then m="apt"
  elif command -v dnf >/dev/null 2>&1; then m="dnf"
  elif command -v yum >/dev/null 2>&1; then m="yum"
  elif command -v pacman >/dev/null 2>&1; then m="pacman"
  elif command -v zypper >/dev/null 2>&1; then m="zypper"
  elif command -v apk >/dev/null 2>&1; then m="apk"
  fi
  VEILNET_PKG_MANAGER="$m"
  printf '%s' "$m"
}

# veilnet_packages_for <manager>: space-separated OS package names.
veilnet_packages_for() {
  case "${1:-}" in
    apt)    printf 'golang-go git wireguard-tools nftables iptables' ;;
    dnf)    printf 'golang git wireguard-tools nftables iptables systemd-resolved' ;;
    yum)    printf 'golang git wireguard-tools nftables iptables' ;;
    pacman) printf 'go git wireguard-tools nftables iptables' ;;
    zypper) printf 'go1.22 git wireguard-tools nftables iptables' ;;
    apk)    printf 'go git wireguard-tools nftables iptables dnsmasq' ;;
    brew)   printf 'go git wireguard-tools' ;;
    *)      printf '' ;;
  esac
}

# veilnet_install_cmd_for <manager> <pkgs...>: full install command line.
veilnet_install_cmd_for() {
  local m="${1:-}"; shift || true
  case "$m" in
    apt)    printf 'sudo apt-get update && sudo apt-get install -y %s' "$*" ;;
    dnf)    printf 'sudo dnf install -y %s' "$*" ;;
    yum)    printf 'sudo yum install -y %s' "$*" ;;
    pacman) printf 'sudo pacman -S --needed --noconfirm %s' "$*" ;;
    zypper) printf 'sudo zypper install -y %s' "$*" ;;
    apk)    printf 'sudo apk add %s' "$*" ;;
    brew)   printf 'brew install %s' "$*" ;;
    *)      printf '' ;;
  esac
}

# veilnet_go_version: "major minor" of the installed Go, or "" if absent.
veilnet_go_version() {
  if ! command -v go >/dev/null 2>&1; then return 0; fi
  go version 2>/dev/null | sed -E 's/.*go([0-9]+)\.([0-9]+).*/\1 \2/' || true
}

# veilnet_check_prereqs: human + machine-readable prerequisite report.
# Prints "ok: ..."/"missing: ..." lines (the --check contract used by
# onboarding). Returns 0 when everything required is present, 1 otherwise.
# DNS helpers (systemd-resolved/dnsmasq) and init systems are advisory only.
veilnet_check_prereqs() {
  local fail=0
  local gv major=0 minor=0
  gv="$(veilnet_go_version || true)"
  if [ -z "$gv" ]; then
    echo 'missing: go (>= 1.22) — not found in PATH; install from https://go.dev/dl/'
    fail=1
  else
    major="${gv%% *}"; minor="${gv##* }"
    if [ "$major" -lt "$VEILNET_GO_MIN_MAJOR" ] || { [ "$major" -eq "$VEILNET_GO_MIN_MAJOR" ] && [ "$minor" -lt "$VEILNET_GO_MIN_MINOR" ]; }; then
      echo "missing: go (>= 1.22) — found $(go version); upgrade from https://go.dev/dl/"
      fail=1
    else
      echo "ok: go $(go version | awk '{print $3}')"
    fi
  fi
  if command -v git >/dev/null 2>&1; then
    echo "ok: git $(git --version | awk '{print $3}')"
  else
    echo 'missing: git — needed to fetch the repo and module deps'
    fail=1
  fi
  if command -v wg >/dev/null 2>&1 || command -v wg-quick >/dev/null 2>&1; then
    echo "ok: wireguard-tools ($(command -v wg 2>/dev/null || command -v wg-quick))"
  else
    echo 'missing: wireguard-tools (wg / wg-quick) — tunnel bring-up needs it'
    fail=1
  fi
  if command -v nft >/dev/null 2>&1; then
    echo 'ok: nftables (nft)'
  elif command -v iptables >/dev/null 2>&1; then
    echo 'ok: iptables (nftables preferred where available)'
  else
    echo 'missing: nftables or iptables — kill-switch firewall needs one of them'
    fail=1
  fi
  # Advisory only: never fail the check for these.
  if command -v resolvectl >/dev/null 2>&1; then
    echo 'ok: systemd-resolved (resolvectl) [advisory]'
  elif command -v dnsmasq >/dev/null 2>&1; then
    echo 'ok: dnsmasq [advisory]'
  else
    echo 'note: no systemd-resolved/dnsmasq found [advisory] — guarded DNS still works, SYSTEM mode is explicit-only'
  fi
  if command -v systemctl >/dev/null 2>&1; then
    echo 'ok: systemd (systemctl) [service install supported]'
  elif [ "$(uname -s 2>/dev/null || echo unknown)" = "Darwin" ]; then
    echo 'ok: launchd (macOS) [service install supported]'
  elif command -v rc-service >/dev/null 2>&1; then
    echo 'ok: OpenRC (rc-service) [see scripts/install.sh note]'
  else
    echo 'note: no systemctl/launchd/OpenRC found [advisory] — run binaries directly'
  fi
  return "$fail"
}

veilnet_distro_notes() {
  case "${1:-}" in
    apt)
      echo 'Notes (apt/Ubuntu/Debian): systemd-resolved ships with systemd (no separate package).'
      echo '  Optional stub resolver: sudo apt-get install -y dnsmasq.'
      echo '  If golang-go is older than 1.22 on your release, install from https://go.dev/dl/ instead.'
      ;;
    dnf|yum)
      echo 'Notes (dnf/yum/Fedora/RHEL): systemd-resolved comes from the systemd-resolved subpackage (listed above).'
      echo '  Optional: sudo dnf install -y dnsmasq. On RHEL, enable EPEL if wireguard-tools is missing.'
      ;;
    pacman)
      echo 'Notes (pacman/Arch/Manjaro): systemd-resolved is part of systemd (systemd-resolvconf for resolv.conf compat).'
      ;;
    zypper)
      echo 'Notes (zypper/openSUSE): Go 1.22+ ships as go1.22; also update-alternatives --config go if several Go slots exist.'
      ;;
    apk)
      echo 'Notes (apk/Alpine): no systemd here — service supervision is OpenRC; see scripts/install.sh.'
      ;;
    brew)
      echo 'Notes (brew/macOS): nftables/iptables do not apply — macOS filters via the built-in pf; DNS via the system resolver.'
      ;;
    brew-missing)
      echo 'Homebrew not found. Install it from https://brew.sh, then: brew install go git wireguard-tools'
      ;;
    none)
      echo 'No supported package manager found. Install go>=1.22, git, wireguard-tools, and nftables/iptables manually,'
      echo 'then re-run ./scripts/setup.sh --check.'
      ;;
  esac
}

usage() {
  sed -n '2,17p' "$0"
}

main() {
  local mode="default" install="0" yes="0"
  while [ $# -gt 0 ]; do
    case "$1" in
      --check) mode="check"; shift ;;
      --dry-run) mode="dryrun"; shift ;;
      --install) install="1"; shift ;;
      --yes|-y) yes="1"; shift ;;
      --help|-h) usage; exit 0 ;;
      *) echo "Unknown flag: $1 (see --help)" >&2; exit 2 ;;
    esac
  done

  veilnet_detect_distro >/dev/null
  veilnet_detect_pkg_manager >/dev/null
  local mgr="$VEILNET_PKG_MANAGER"
  local pkgs
  pkgs="$(veilnet_packages_for "$mgr")"

  echo "VeilNet setup: ${VEILNET_DISTRO_NAME} (${VEILNET_DISTRO_ID} ${VEILNET_DISTRO_VERSION}) — package manager: ${mgr}"

  if [ "$mode" = "check" ]; then
    veilnet_check_prereqs
    exit $?
  fi

  if [ "$mode" = "dryrun" ]; then
    if [ -n "$pkgs" ]; then
      echo "Would run: $(veilnet_install_cmd_for "$mgr" "$pkgs")"
    else
      echo "No install command for manager '$mgr'."
    fi
    veilnet_distro_notes "$mgr"
    echo 'Dry run: nothing changed.'
    exit 0
  fi

  # Default mode: report prereqs (never fail the legacy go-mod step on
  # missing *system* packages), then do the Go-side setup idempotently.
  if ! veilnet_check_prereqs; then
    echo ''
    if [ -n "$pkgs" ]; then
      echo "Install OS packages with: $(veilnet_install_cmd_for "$mgr" "$pkgs")"
      echo '  or re-run with: ./scripts/setup.sh --install'
    fi
    veilnet_distro_notes "$mgr"
  fi

  if [ "$install" = "1" ]; then
    if [ -z "$pkgs" ]; then
      echo "Cannot --install: no package list for manager '$mgr'." >&2
      veilnet_distro_notes "$mgr"
      exit 1
    fi
    if [ "$yes" != "1" ]; then
      printf 'About to run: %s [y/N] ' "$(veilnet_install_cmd_for "$mgr" "$pkgs")"
      read -r ans < /dev/tty || ans=""
      case "$ans" in
        [yY]|[yY]es) ;;
        *) echo 'Aborted. Nothing changed.'; exit 0 ;;
      esac
    fi
    # Idempotent: package managers skip already-installed packages.
    # shellcheck disable=SC2086
    case "$mgr" in
      apt) sudo apt-get update && sudo apt-get install -y $pkgs ;;
      dnf) sudo dnf install -y $pkgs ;;
      yum) sudo yum install -y $pkgs ;;
      pacman) sudo pacman -S --needed --noconfirm $pkgs ;;
      zypper) sudo zypper install -y $pkgs ;;
      apk) sudo apk add $pkgs ;;
      brew) brew install $pkgs ;;
    esac
    echo ''
    echo 'Re-checking after install:'
    veilnet_check_prereqs || true
  fi

  if ! command -v go >/dev/null 2>&1; then
    echo 'Go toolchain not found in PATH. Install Go 1.22+ from https://go.dev/dl/ and re-run.' >&2
    exit 1
  fi
  gv="$(veilnet_go_version || true)"
  major="${gv%% *}"; minor="${gv##* }"
  if [ "$major" -lt "$VEILNET_GO_MIN_MAJOR" ] || { [ "$major" -eq "$VEILNET_GO_MIN_MAJOR" ] && [ "$minor" -lt "$VEILNET_GO_MIN_MINOR" ]; }; then
    echo "Go 1.22+ required, found $(go version)." >&2
    exit 1
  fi
  echo "Found: $(go version)"

  export GOTOOLCHAIN=local
  go mod download all

  echo 'Setup complete. Next: ./scripts/build.sh'
}

# Execute only when run, not when sourced (sourcing is the test contract).
if [ -z "${VEILNET_SETUP_NOEXEC:-}" ] && [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
  main "$@"
fi
