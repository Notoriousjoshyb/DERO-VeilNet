#!/usr/bin/env bash
# Unit tests for scripts/setup.sh detection logic (shell, not Go).
# Sources setup.sh without executing it, then exercises
# veilnet_detect_distro / veilnet_detect_pkg_manager / veilnet_packages_for
# against fixture os-release files plus the live /etc/os-release path.
#
#   bash deploy/packaging/tests/test_detect.sh
set -euo pipefail

HERE="$(dirname "$0")"
# shellcheck source=../../scripts/setup.sh
VEILNET_SETUP_NOEXEC=1 source "$HERE/../../../scripts/setup.sh"

pass=0
fail=0

assert_eq() {
  local label="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
    echo "ok: $label ($got)"
  else
    fail=$((fail + 1))
    echo "FAIL: $label — want '$want', got '$got'" >&2
  fi
}

# --- distro detection per fixture -------------------------------------------
check_fixture() {
  local name="$1" want_id="$2"
  VEILNET_DISTRO_ID="" VEILNET_DISTRO_LIKE="" VEILNET_DISTRO_VERSION="" VEILNET_DISTRO_NAME=""
  got="$(VEILNET_OS_RELEASE="$HERE/fixtures/os-release.$name" veilnet_detect_distro "$HERE/fixtures/os-release.$name")"
  assert_eq "distro:$name" "$want_id" "$got"
}

check_fixture ubuntu ubuntu
check_fixture debian debian
check_fixture fedora fedora
check_fixture rhel rhel
check_fixture arch arch
check_fixture manjaro arch     # derivative normalizes to family
check_fixture opensuse opensuse-tumbleweed
check_fixture alpine alpine

# Missing file on non-macOS yields unknown (never errors).
VEILNET_DISTRO_ID=""
got="$(veilnet_detect_distro "$HERE/fixtures/os-release.does-not-exist")"
case "$(uname -s)" in
  Darwin) assert_eq "distro:missing-file(macos)" "macos" "$got" ;;
  *) assert_eq "distro:missing-file" "unknown" "$got" ;;
esac

# Live /etc/os-release path: must always succeed and print something.
if [ -f /etc/os-release ]; then
  VEILNET_DISTRO_ID=""
  got="$(veilnet_detect_distro)"
  if [ -n "$got" ] && [ "$got" != "unknown" ]; then
    pass=$((pass + 1))
    echo "ok: live /etc/os-release -> $got"
  else
    fail=$((fail + 1))
    echo "FAIL: live /etc/os-release yielded '$got'" >&2
  fi
else
  echo "skip: no live /etc/os-release on this machine ($(uname -s))"
fi

# --- package manager override + package lists --------------------------------
VEILNET_PKG_MANAGER="apt"
assert_eq "mgr:override" "apt" "$(veilnet_detect_pkg_manager)"
assert_eq "pkgs:apt" "golang-go git wireguard-tools nftables iptables" "$(veilnet_packages_for apt)"
assert_eq "pkgs:dnf" "golang git wireguard-tools nftables iptables systemd-resolved" "$(veilnet_packages_for dnf)"
assert_eq "pkgs:yum" "golang git wireguard-tools nftables iptables" "$(veilnet_packages_for yum)"
assert_eq "pkgs:pacman" "go git wireguard-tools nftables iptables" "$(veilnet_packages_for pacman)"
assert_eq "pkgs:zypper" "go1.22 git wireguard-tools nftables iptables" "$(veilnet_packages_for zypper)"
assert_eq "pkgs:apk" "go git wireguard-tools nftables iptables dnsmasq" "$(veilnet_packages_for apk)"
assert_eq "pkgs:brew" "go git wireguard-tools" "$(veilnet_packages_for brew)"

# Every supported manager must produce a non-empty install command.
for m in apt dnf yum pacman zypper apk brew; do
  cmd="$(VEILNET_PKG_MANAGER="$m" veilnet_install_cmd_for "$m" "$(veilnet_packages_for "$m")")"
  if [ -n "$cmd" ]; then
    pass=$((pass + 1))
    echo "ok: install-cmd:$m"
  else
    fail=$((fail + 1))
    echo "FAIL: install-cmd:$m empty" >&2
  fi
done
VEILNET_PKG_MANAGER=""

# Live manager detection must always succeed (value may be "none").
VEILNET_PKG_MANAGER=""
got="$(veilnet_detect_pkg_manager)"
if [ -n "$got" ]; then
  pass=$((pass + 1))
  echo "ok: live pkg manager -> $got"
else
  fail=$((fail + 1))
  echo "FAIL: live pkg manager detection empty" >&2
fi

# --- check mode is side-effect free ------------------------------------------
if bash "$HERE/../../../scripts/setup.sh" --check >/dev/null 2>&1; then
  pass=$((pass + 1))
  echo "ok: --check exit 0 (prereqs satisfied)"
else
  # Non-zero is fine on machines without wireguard-tools; it must still print.
  out="$(bash "$HERE/../../../scripts/setup.sh" --check 2>&1 || true)"
  case "$out" in
    *"ok: "*|*"missing: "*) pass=$((pass + 1)); echo "ok: --check reports (prereqs missing, format valid)" ;;
    *) fail=$((fail + 1)); echo "FAIL: --check output unparseable" >&2 ;;
  esac
fi

echo "---"
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
