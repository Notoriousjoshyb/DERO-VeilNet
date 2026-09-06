# VeilNet Platform Matrix

All OS decisions live in `internal/platform` (owned by PlatformCoreAgent).
Subsystem managers (`firewall`, `dns`, `routing`, `tunnel`) consume the
`platform` contracts and per-OS backend files; shared logic never switches
on `runtime.GOOS`.

## Mechanisms per OS

| Concern | Windows 11 | Linux (Ubuntu/Debian, Fedora/RHEL, Arch, openSUSE) | macOS |
|---|---|---|---|
| Kill switch | `netsh advfirewall` named allow rules + outbound block default | nftables table `veilnet` (chains `out`/`in`, default drop); iptables fallback if `nft` fails | pf anchor `com.veilnet.killswitch` + `pfctl -e` |
| DNS | `netsh interface ip set/add dns` + NRPT catch-all `VeilNet-CatchAll` | `resolvectl dns <iface>` + `resolvectl domain <iface> ~.`; fallback: rewrite `/etc/resolv.conf` | `networksetup -setdnsservers <service>`; leak query falls back to `scutil --dns` |
| DoH | `netsh dns add encryption` (known templates only, unknown rejected) | explicit error (no silent downgrade) | explicit error (no silent downgrade) |
| Routes | `netsh interface ipv4 add/delete route`, interface metric | `ip route add/del`, `ip link set metric` | `route -n add/delete -inet`, `route -n add/delete -inet6` |
| IPv6 leak block | netsh block rule `::/0` + router-discovery off on tunnel iface | `ip -6 route add blackhole ::/0` | `route -n add -inet6 ::/0 ::1 -blackhole` |
| TUN backend | kernel if `WireGuardNT` service present and iface exists, else Wintun/userspace | kernel if module/dry-run probe passes and iface exists, else userspace | userspace over utun (no kernel backend) |
| App dirs | `%AppData%/veilnet` (config), `%LocalAppData%/veilnet` (+`state`) | XDG (`~/.config`, `~/.local/share`, `~/.local/state`) | `~/Library/Application Support/veilnet`, `~/Library/Caches/veilnet` |
| Service | SCM service `veilnet` (`veilnet-service.exe`) | systemd unit `veilnet` | launchd label `net.veilnet.daemon` |

Backend probe names (`platform.Register`): firewall `netsh`/`nftables`/`pf`;
dns `netsh-nrpt`/`systemd-resolved`/`networksetup`; route
`netsh`/`ip-route`/`bsd-route`. `Supports()` is true only on the matching
OS. Managers expose `BackendName()` for diagnostics.

## Privilege requirements

`platform.IsAdmin()` (Windows token membership / `geteuid() == 0` elsewhere)
gates the data plane. `platform.NeedsPrivilegedService()` is always true:
TUN creation, firewall, routes and DNS all require elevation.
`platform.PrivilegeHint()` and `ServiceSpec.InstallHint()` name the fix:

- Windows: run as Administrator, or
  `sc create veilnet binPath= "veilnet-service.exe" start= auto && sc start veilnet`
- Linux: re-run with sudo, or
  `sudo cp packaging/systemd/veilnet.service /etc/systemd/system/ && sudo systemctl enable --now veilnet`
- macOS: re-run with sudo, or
  `sudo cp packaging/launchd/net.veilnet.daemon.plist /Library/LaunchDaemons/ && sudo launchctl load /Library/LaunchDaemons/net.veilnet.daemon.plist`

Onboarding surfaces `platform.DefaultService().InstallHint()` verbatim in
"service not installed" errors.

## Limitations (honest, no silent downgrade)

- DoH mode is Windows 11 only. Linux/macOS return an explicit error naming
  the cause; unknown DoH servers are rejected on every OS.
- Linux `/etc/resolv.conf` fallback drops non-`nameserver` directives
  (`search`, `options`); the systemd-resolved path preserves everything.
- macOS `networksetup` addresses one service: pass the tunnel *service*
  name (usually the interface name). There is no system-wide NRPT
  equivalent; `LeakState` reports any non-tunnel resolver as a leak.
- macOS has no interface-metric primitive (`SetMetric` errors explicitly);
  route scope is per-route.
- Enabling pf (`pfctl -e`) is host-global; Disable restores the exact
  prior pf state (re-disables only if it was disabled).
- OSes without a backend (`unsupported(...)`) fail every mutation loudly
  instead of running unprotected. No fake protection states anywhere.
- State migration: sentinels moved from `~/.veilnet` to the platform state
  dir; the legacy path is still read and cleaned once, then removed.
