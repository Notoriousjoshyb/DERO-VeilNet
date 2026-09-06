# VeilNet Install Guide

Zero-friction defaults: every path below is copy-paste, with no manual
dependency hunting. Pick your OS, run the blocks in order, and you end with a
running client. Node operators add one extra step at the end.

First-run behavior (all platforms): with no config file present, `veilnet`
starts with sane defaults, auto-picks the fastest known node, and asks for
explicit payment approval before spending anything. If something is missing,
errors name the fix (e.g. service not installed → the one-command install).

> Privacy rules (binding): no analytics/telemetry, no traffic logging, DERO
> never carries user traffic, never auto-spend (explicit approval only).

Prerequisites on every OS: Go 1.22+, git, wireguard-tools, and a firewall
backend (nftables or iptables on Linux; built-in pf on macOS; Windows
Filtering Platform on Windows, no extra package).

---

## Windows 11 (PowerShell, copy-paste)

```powershell
# 1. Prerequisites (winget; choco alternatives in comments)
winget install -e --id GoLang.Go
winget install -e --id WireGuard.WireGuard
# choco install golang wireguard -y

# 2. Check + fetch module deps
.\scripts\setup.ps1
# check-only mode (used by first-run onboarding): .\scripts\setup.ps1 -Check

# 3. Build
.\scripts\build.ps1

# 4. Install + start the privileged service (ELEVATED prompt)
.\scripts\install-service.ps1
sc.exe start VeilNetService

# 5. Run the client
.\dist\veilnet.exe
```

MSI (optional, needs WiX): `winget install -e --id FireGiant.WiX`,
then see `docs/PACKAGING.md`. Without WiX, ship `dist\*.exe` as a zip.

---

## Ubuntu / Debian (apt)

```sh
# 1. OS packages (Go 1.22+, git, WireGuard, firewall)
sudo apt-get update && sudo apt-get install -y golang-go git wireguard-tools nftables iptables
# If golang-go on your release is older than 1.22, install from https://go.dev/dl/ instead.
# Optional stub resolver: sudo apt-get install -y dnsmasq
# (systemd-resolved ships with systemd — no separate package.)

# 2. Check + fetch module deps (or: ./scripts/setup.sh --install to automate step 1)
./scripts/setup.sh
# check-only: ./scripts/setup.sh --check | dry run: ./scripts/setup.sh --dry-run

# 3. Build (reproducible: VERSION + SOURCE_DATE_EPOCH stamped to dist/VERSION)
./scripts/build.sh

# 4. Install binaries + systemd unit, enable on boot, start now
sudo ./scripts/install.sh --start

# 5. Run the client
veilnet
```

Service control: `systemctl status veilnet.service`.

---

## Fedora / RHEL (dnf / yum)

```sh
# 1. OS packages
sudo dnf install -y golang git wireguard-tools nftables iptables systemd-resolved
# RHEL with yum: sudo yum install -y golang git wireguard-tools nftables iptables
# On RHEL, enable EPEL first if wireguard-tools is missing.
# Optional: sudo dnf install -y dnsmasq

# 2-5. Same as Ubuntu:
./scripts/setup.sh
./scripts/build.sh
sudo ./scripts/install.sh --start
veilnet
```

---

## Arch / Manjaro (pacman)

```sh
# 1. OS packages
sudo pacman -S --needed --noconfirm go git wireguard-tools nftables iptables
# (systemd-resolved is part of systemd; systemd-resolvconf for resolv.conf compat.)

./scripts/setup.sh
./scripts/build.sh
sudo ./scripts/install.sh --start
veilnet
```

---

## openSUSE (zypper)

```sh
# 1. OS packages
sudo zypper install -y go1.22 git wireguard-tools nftables iptables
# If several Go slots exist: sudo update-alternatives --config go

./scripts/setup.sh
./scripts/build.sh
sudo ./scripts/install.sh --start
veilnet
```

---

## macOS (Homebrew)

```sh
# 1. OS packages (pf firewall and system resolver are built in — nothing to install)
brew install go git wireguard-tools
# No Homebrew yet? Install from https://brew.sh first.

./scripts/setup.sh
./scripts/build.sh

# 4. Install binaries + launchd daemons (root for system-wide, or --user)
sudo ./scripts/install.sh --start
# current-user only: ./scripts/install.sh --user

# 5. Run the client
veilnet
```

Start/stop manually:
`sudo launchctl bootstrap system /Library/LaunchDaemons/com.veilnet.service.plist`.

---

## Alpine / OpenRC note

```sh
sudo apk add go git wireguard-tools nftables iptables dnsmasq
./scripts/setup.sh
./scripts/build.sh
sudo ./scripts/install.sh   # prints the OpenRC /etc/init.d example (no systemd here)
```

---

## Node operators (any OS, after the client steps)

```sh
# Linux: enable the node unit (installed but intentionally not enabled by default)
sudo systemctl enable --now veilnet-node.service
# macOS: sudo launchctl bootstrap system /Library/LaunchDaemons/com.veilnet.node.plist
# Windows: run dist\veilnet-node.exe run (service hosting for the node is out of scope for the MSI)

veilnet-node init-config
veilnet-node run
```

Read `docs/NODE_OPERATOR.md` (bonding, pricing, capacity) and
`docs/SECURITY.md` (exit-node legal exposure) before announcing a node.

---

## Troubleshooting (errors name the fix)

| Symptom | Fix (one command) |
|---|---|
| `Go toolchain not found` / `Go 1.22+ required` | Install Go from https://go.dev/dl/, or per-OS step 1 above |
| `missing: wireguard-tools` | Per-OS step 1, or `./scripts/setup.sh --install` |
| `service not installed` (client can't reach the service) | Linux: `sudo ./scripts/install.sh --start`; macOS: `sudo ./scripts/install.sh --start`; Windows (elevated): `.\scripts\install-service.ps1; sc.exe start VeilNetService` |
| `Missing dist/...` from install/package | `./scripts/build.sh` (or `--build` flag on install) |
| Payment prompt on first connect | Expected: VeilNet never auto-spends; approve explicitly each time |

Uninstall: `sudo ./scripts/uninstall.sh` (keeps `~/.veilnet`; add `--purge`
to delete config/state too). Per-user installs: `./scripts/uninstall.sh --user`.
