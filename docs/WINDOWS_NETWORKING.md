# Windows networking: what VeilNet actually does

This document describes the real commands and APIs used by
`internal/tunnel`, `internal/wireguard`, `internal/routing`,
`internal/firewall` and `internal/dns`. If the code and this file ever
disagree, the code wins and this file must be updated.

All privileged operations require elevation. Without admin rights the
engine returns an error (`FAILED` state) instead of pretending to work.

## 1. Data plane (internal/tunnel + internal/wireguard)

### Preferred path: WireGuardNT-managed interface via wgctrl

Production deployments run the official WireGuardNT driver/service
(`wireguard.exe`), which owns an OS interface named `veilnet`.
The engine detects it with `wgctrl.Device("veilnet")` and configures it
with `wgctrl.ConfigureDevice` (full peer replace on Start/Apply, peer
clear on Stop). Package used: `golang.zx2c4.com/wireguard/wgctrl`
(`wgtypes.Config` / `wgtypes.PeerConfig`). No custom crypto anywhere:
keys are `wgtypes` keys; key generation uses `crypto/rand` +
`curve25519.X25519` from `golang.org/x/crypto`.

### Fallback: embedded wireguard-go userspace device

When no `veilnet` interface exists, the engine embeds wireguard-go:

- TUN: `tun.CreateTUN("veilnet", 1420)` (Wintun on Windows).
- UDP: `conn.NewDefaultBind()` (WinRing on Windows); the listen port is
  applied through the IPC blob (`listen_port=`).
- Config: `device.IpcSet()` with the output of
  `internal/wireguard.ToIPC` (hex keys, `endpoint=`, `allowed_ip=`,
  `persistent_keepalive_interval=`). Addresses and DNS never enter the
  IPC blob — they belong to the TUN/routing/DNS layers.
- Stats/state: `device.IpcGet()` parsed by `ParseIPCDump`/`AggregateStats`
  (`rx_bytes`, `tx_bytes`, `last_handshake_time_sec`). `Status()` reports
  `UP` only with a live device plus a fresh handshake; otherwise
  `CONNECTING`, and `FAILED` after the watchdog exhausts retries.
- Rebind (NAT / sleep recovery): `device.BindUpdate()`.

Unit tests (`internal/tunnel/engine_test.go`) peer two real devices over
127.0.0.1 with in-memory TUNs and `StdNetBindFactory` (classic sockets):
WinRing RIO receive does not deliver loopback datagrams in that harness,
so tests pin the std bind while production keeps `NewDefaultBind`.

Key files: `internal/tunnel/engine.go`, `internal/tunnel/backend.go`,
`internal/tunnel/monitor.go`, `internal/wireguard/wgconf.go`.

### Sleep / wake

No WNF/WMI dependency in the engine. The watchdog treats a wall-clock
jump (> 5× poll interval + 60 s) as suspend/resume and forces
`BindUpdate()` with backoff reset. The service layer should additionally
call `Engine.Wake()` on `WM_POWERBROADCAST / PBT_APMRESUME`.

## 2. Routing (internal/routing)

Windows commands issued via `netsh` (names quoted, so renames survive):

```
netsh interface ipv4 add route 0.0.0.0/0 "veilnet" <tun-gw> metric=5
netsh interface ipv4 delete route 0.0.0.0/0 "veilnet" <tun-gw>
netsh interface ipv4 add route <peer-ip>/32 "<orig-if>" <orig-gw> metric=1
netsh interface ipv4 delete route <peer-ip>/32 "<orig-if>" <orig-gw>
netsh interface ipv4 set interface "veilnet" metric=5
```

- The `/32` bypass keeps the handshake endpoint reachable after the
  default route moves into the tunnel.
- Previous interface metrics are recorded and restored on `RemoveAll`.
- Added routes persist to `%USERPROFILE%\.veilnet\routes.json`; a new
  `Manager` deletes stale entries first (crash recovery).
- Linux/macOS use the same `Manager` API over `ip route add/del` and
  `route -n add/delete -inet` respectively (best effort, same symmetry).

### IPv6: blocked unless explicitly routed

```
netsh advfirewall firewall add rule name=VeilNet-IPv6-Block dir=out action=block remoteip=::/0 description="VeilNet IPv6 leak block"
netsh interface ipv6 set interface "veilnet" routerdiscovery=disabled managedaddress=disabled otherstateful=disabled
```

Reversed by `RestoreIPv6` / `RemoveAll` (rule delete). Physical adapters
are never reconfigured — only the tunnel interface plus a global
firewall egress block, so a failure cannot strand the machine without
IPv4.

## 3. Kill switch (internal/firewall)

`netsh advfirewall firewall` rules in group `"VeilNet Kill Switch"`:

```
add rule group="VeilNet Kill Switch" name=VeilNet-KS-Allow-Endpoint dir=out action=allow protocol=UDP remoteip=<peer-ip> remoteport=<port>
add rule ... name=VeilNet-KS-Allow-Tunnel-Out dir=out action=allow localip=<tun-addr>
add rule ... name=VeilNet-KS-Allow-Tunnel-In dir=in action=allow remoteip=<tun-addr>
add rule ... name=VeilNet-KS-Allow-DHCP-Out dir=out action=allow protocol=UDP remoteip=255.255.255.255 remoteport=67
add rule ... name=VeilNet-KS-Allow-DHCP-In dir=in action=allow protocol=UDP localport=68
add rule ... name=VeilNet-KS-Allow-LAN dir=out action=allow remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16   # only with WithLANAllowed(true)
```

Allow-listing works by switching the outbound default first:

```
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
```

The previous policy (queried via `netsh advfirewall show allprofiles`,
defaulting to `blockinbound,allowoutbound` on unparsable output) is
stored in `%USERPROFILE%\.veilnet\killswitch.json` along with the rule
names, and restored by `Disable()`.

- Fail-closed: on tunnel `FAILED` the app calls `FailClosed()`, which
  re-asserts the block policy and keeps the rules. Rules are removed
  only by an explicit `Disable()` (user Stop) or by the next `Enable()`
  reconciling a stale sentinel after a crash.
- Modes: `OFF` (Disable), `ON_WHILE_CONNECTED` (rules live with the
  session), `ALWAYS_ON` (same enforcement; the app keeps them across
  Stop and re-applies at boot).
- Event: `KILL_SWITCH_ENABLED` on `Enable` and on `FailClosed`.

## 4. DNS (internal/dns)

```
netsh interface ip set dns name="veilnet" static <primary>
netsh interface ip add dns name="veilnet" <extra> index=2
netsh interface ip set dns name="veilnet" dhcp            # restore path
```

NRPT catch-all (PowerShell, rule name `VeilNet-CatchAll`, removed only by
name match so system rules are never touched):

```powershell
Get-DnsClientNrptRule -Name "VeilNet-CatchAll" -ErrorAction SilentlyContinue | Remove-DnsClientNrptRule -Force
Add-DnsClientNrptRule -Namespace "." -NameServers "<ip1>,<ip2>" -Name "VeilNet-CatchAll" -Comment "VeilNet managed"
```

DoH (Windows 11) per resolver before use:

```
netsh dns add encryption server=<ip> dohtemplate=<template> autoupgrade=yes
```

Known templates: `1.1.1.1`/`1.0.0.1` → Cloudflare,
`8.8.8.8`/`8.8.4.4` → Google, `9.9.9.9` → Quad9. Unknown servers are
rejected rather than silently downgraded.

- The pre-VeilNet resolver set is snapshotted to
  `%USERPROFILE%\.veilnet\dns.json` before the first change and restored
  by `Restore()`.
- `LeakState()` returns `{resolvers, route, leaking}` where `route` is
  `"tunnel"` only when every effective resolver (`Get-DnsClientServerAddress`)
  is tunnel-scoped; anything else (including `SYSTEM` mode, which is an
  explicit user opt-out) reports `leaking: true`.
- Modes: `VEILNET` (node resolvers), `CUSTOM` (user resolvers),
  `DOH` (templates required), `SYSTEM` (explicit restore, no NRPT).
- Event: `DNS_CHANGED` on `Apply`/`Restore`.

## 5. Event wiring (who publishes what)

| Component | Events |
|---|---|
| tunnel engine | `TUNNEL_STARTED` (after device up), `TUNNEL_STOPPED` (after Stop), `CIRCUIT_ROTATED` (RotateEndpoint), `ERROR` (Start failure, watchdog exhaustion) |
| firewall | `KILL_SWITCH_ENABLED` (Enable, FailClosed) |
| dns | `DNS_CHANGED` (Apply, Restore) |

The app layer is expected to call `firewall.FailClosed()` on tunnel
`ERROR`/`FAILED`, and `routing.RemoveAll()` + `firewall.Disable()` +
`dns.Restore()` on explicit Stop — in that order.
