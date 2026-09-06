<p align="center">
  <img src="docs/assets/veilnet-logo-720.png" alt="DERO VeilNet" width="320">
</p>

<h1 align="center">DERO // VEILNET</h1>

<p align="center">
  Decentralized privacy VPN: WireGuard data plane, DERO control plane.<br>
  Windows 11 first; Linux/macOS portable.
</p>

> Privacy rules (binding): no analytics/telemetry, no traffic-content
> logging, DERO NEVER carries user traffic, never auto-spend DERO (explicit
> approval only), never put secret keys on-chain.

## Contents

- [What](#what) · [How](#how)
- **[Full setup](#full-setup)** — install and build, every OS
- **[End user guide](#end-user-guide)** — use the VPN client
- **[VPN host guide](#vpn-host-guide)** — run an exit or relay node
- [Troubleshooting](#troubleshooting) · [Arch](#arch) · [Dev](#dev)
- [Limitations (honest)](#limitations-honest) · [Roadmap](#roadmap)

## What

VeilNet lets clients buy private VPN exits from independent node operators,
coordinated over DERO. Nodes advertise themselves (endpoint, region, price,
capacity, bond) in a registry; clients pick by latency/load/price/uptime and
local history, approve payment explicitly, receive a single-use session
token, and bring up a WireGuard tunnel. A privileged local service hosts the
tunnel, kill switch, and DNS so the UI never needs admin rights.

## How

```text
Client → discover nodes → explicit DERO approval → session authorized
  → WireGuard tunnel UP → kill switch + guarded DNS + IPv6 route-or-block
  → traffic exits via the node. DERO only coordinates; it never sees traffic.
```

- **Session:** prepaid approval-split payment → `Approval`/`Credit` →
  single-use bearer token (256-bit, expiring, revocation sticks).
- **Safety:** kill switch `OFF / ON_WHILE_CONNECTED / ALWAYS_ON`;
  DNS `VEILNET / CUSTOM / DOH / SYSTEM-explicit-only`;
  IPv6 routed securely or blocked — never a silent leak.
- **Wallet:** connect your own DERO wallet — **XSWD** (wallet-to-dApp
  socket; the wallet renders every prompt) or **wallet JSON-RPC**
  (local endpoint, optional `--rpc-login`). VeilNet never sees a seed or
  key and never auto-spends. Wallet-less use stays fully supported.
- **Demo:** `veilnet --demo` runs badged and isolated from prod state.

---

# Full setup

Three programs are built from this repo. You do not need all three.

| Binary | Who needs it | What it does |
| ------ | ------------ | ------------ |
| `veilnet.exe` | end users | the client app (GUI + CLI). Never needs admin. |
| `veilnet-service.exe` | end users | privileged service: owns the tunnel, kill switch and DNS. Installed once. |
| `veilnet-node.exe` | VPN hosts | the exit/relay node daemon. |

There are no installers yet (MSI is planned). Build from source.

**Prerequisites, every OS:** Go 1.22+, git, WireGuard tools, and a firewall
backend — nftables/iptables on Linux, built-in pf on macOS, Windows
Filtering Platform on Windows (nothing extra to install).

## Windows 11

```powershell
# 1. Prerequisites
winget install -e --id GoLang.Go
winget install -e --id WireGuard.WireGuard

# 2. Fetch module deps (check only: .\scripts\setup.ps1 -Check)
.\scripts\setup.ps1

# 3. Build all three binaries into dist\
.\scripts\build.ps1

# 4. Install + start the privileged service — ELEVATED PowerShell
.\scripts\install-service.ps1
sc.exe start VeilNetService

# 5. Run the client (normal, non-admin prompt)
.\dist\veilnet.exe
```

Step 5 opens the UI in your browser at `http://127.0.0.1:18280`.

Skip step 4 to try demo mode only: `.\dist\veilnet.exe --demo`.

## Linux / macOS

```sh
./scripts/setup.sh      # check + fetch deps (./scripts/setup.sh --install to add OS packages)
./scripts/build.sh      # build into dist/
./scripts/test.sh       # optional: run the scoped test suites
./dist/veilnet          # run the client
```

The service on Linux/macOS listens on `127.0.0.1:18441` instead of a
Windows named pipe. Per-distro package lists live in `docs/INSTALL.md`.

## Where files live

| Path | Contents |
| ---- | -------- |
| `~/.veilnet/config.toml` | client config — **created for you on first run** |
| `~/.veilnet/demo-config.toml` | demo config, isolated from the real one |
| `~/.veilnet/service.token` | IPC auth token (`0600`) |
| `~/.veilnet-node/config.toml` | node config |
| `~/.veilnet-node/mgmt.token` | node control-API bearer token (`0600`) |
| `~/.veilnet-node/clients.db` | node session accounting |
| `.veilnet-dev/` | devnet state — never touches production paths |

## Check your environment

```powershell
.\dist\veilnet.exe --setup
```

This prints an environment report. Every problem it finds names the fix.

---

# End user guide

## 1. Start the app

```powershell
.\dist\veilnet.exe                 # GUI, opens a browser tab
.\dist\veilnet.exe --demo          # GUI with fake nodes, badged DEMO
.\dist\veilnet.exe --no-browser    # start the UI, do not open a tab
```

Nothing to configure. First run writes `~/.veilnet/config.toml` with safe
defaults: FASTEST policy, VeilNet DNS, kill switch `ON_WHILE_CONNECTED`,
IPv6 blocked, no auto-spend.

## 2. Take the tour

The **Get started** screen walks five steps: welcome → how it works →
speed and region → connect → done. Press **Skip tour** any time.

## 3. Connect your DERO wallet (only needed for paid nodes)

Open the **Wallet** screen and pick one mode:

| Mode | Endpoint | How approval works |
| ---- | -------- | ------------------ |
| **XSWD** (recommended) | `ws://127.0.0.1:44326/xswd` | Your wallet shows the prompt. Approve VeilNet once, then approve each payment. |
| **Wallet RPC** | `http://127.0.0.1:10103` | VeilNet talks to your local wallet RPC server. Fill in user + password only if you started the wallet with `--rpc-login user:pass`. Basic **and** Digest challenges are handled. |
| **No wallet** | — | Demo and free nodes still work. Paid nodes will not connect. |

Tick **Remember these settings** to reconnect without retyping. Connecting
only reads your address and balance. Nothing is spent by connecting.

**XSWD steps:** open your DERO wallet → turn on XSWD → press **Connect
wallet** in VeilNet → approve the prompt in the wallet window.

## 4. Connect to a node

Three ways, all equivalent:

- **Home** → press the big dial, or the **Connect** button. VeilNet
  auto-picks by your policy.
- **Nodes** → filter, sort by any column, press **Connect** on one row.
- **Locations** → click a city card to use its best node.

A paid node opens an approval dialog first with the exact price per hour.
Decline and nothing is spent.

The status reads **PROTECTED** only when the tunnel is really up.

## 5. Read the screens

| Screen | Shows |
| ------ | ----- |
| **Home** | connection dial, elapsed time, bytes in/out, live throughput graph |
| **Locations** | one card per city: node count, best latency, cheapest price, load |
| **Nodes** | full table: price, latency, load bar, trust score, status |
| **Circuit** | the hop chain, pinned entry guard, rotate exit, build 2- or 3-hop |
| **Wallet** | wallet mode, address, balance, spendable |
| **Payment** | budget cap, spend last hour, receipts, and the send form |
| **Privacy** | live checks: tunnel, exit IP, DNS, IPv6, kill switch, node, multihop |
| **DERO** | control-plane RPC endpoint and network |
| **Settings** | kill switch, DNS, region, auto-connect, multihop, IPv6 |
| **Diagnostics** | the raw JSON report, with a copy button |

## 6. Settings that matter

| Setting | Options | Pick this |
| ------- | ------- | --------- |
| Kill switch | `Off` / `On while connected` / `Always on` | **On while connected**. `Always on` blocks all traffic when the tunnel is down. |
| DNS mode | `VeilNet resolver` / `Custom` / `DoH` / `System` | **VeilNet resolver**. `System` leaks your DNS to your ISP — it is explicit opt-in only. |
| Route IPv6 | on / off | **Off**. Off blocks IPv6 so it cannot leak around the tunnel. |
| Multihop | on / off | Off for speed, on for more privacy (see Circuit). |
| Auto-connect | on / off | On if you want the tunnel up at launch. |

Press **Save settings**. Changes persist across restarts.

## 7. Pay for a session

1. **Payment** → **Request approval**. This flags a pending approval; it
   spends nothing.
2. Fill in the destination address and the amount.
3. **Review and send** → confirm in the VeilNet dialog.
4. In XSWD mode your wallet asks a second time. Approve there too.

VeilNet refuses to send when no approval is pending, when no wallet is
connected, or when the amount is over your budget cap.

## 8. Command line

```powershell
.\dist\veilnet.exe --status              # print state JSON and exit
.\dist\veilnet.exe --connect             # auto-select and connect
.\dist\veilnet.exe --connect demo-eu-01  # connect to a named node
.\dist\veilnet.exe --disconnect          # tear the tunnel down
.\dist\veilnet.exe --setup               # environment report + fix hints
.\dist\veilnet.exe --demo --connect      # demo connect with live stats
```

Headless commands go through the privileged service. The GUI itself never
needs admin rights.

---

# VPN host guide

You run a node to sell exits or relay hops. Read `docs/SECURITY.md`
first: **exit nodes carry real legal exposure.**

## Node types

| Type | Meaning |
| ---- | ------- |
| `EXIT` | Client traffic leaves to the public internet from your machine. Needs `abuse_contact` and `jurisdiction`. |
| `RELAY` | Multihop middle only. Forwards encrypted tunnels, never exits. Exit-scoped tokens are rejected. |

## 1. Create the config

```powershell
.\dist\veilnet-node.exe init-config
```

This writes `~/.veilnet-node/config.toml` and a management token at
`~/.veilnet-node/mgmt.token`.

## 2. Edit the config

At minimum set these:

```toml
node_type            = "EXIT"          # or "RELAY"
region               = "eu-west"
country              = "DE"
city                 = "Frankfurt"
public_endpoint      = "203.0.113.10:51820"   # the ip:port clients dial
price_per_hour_dero  = 0.01
max_clients          = 50
dero_address         = "dero1q..."     # your payout address (public only)
abuse_contact        = "abuse@example.org"    # required for EXIT
jurisdiction         = "DE"                   # required for EXIT
```

Full key reference:

| Key | Default | Notes |
| --- | ------- | ----- |
| `node_type` | `EXIT` | `EXIT` or `RELAY` |
| `region/country/city` | local/dev | advertised metadata |
| `max_clients` | 50 | capacity; past this, authorize returns `429` |
| `bandwidth_down/up_mbps` | 100/100 | advertised + status display |
| `price_per_hour_dero` | 0.01 | the client approves every payment |
| `accept_new` | true | set `false` to drain the node (`503`) |
| `public_endpoint` | — | `ip:port` clients dial |
| `dero_address` | — | payouts, public address only |
| `bond_dero` | 0 | informational until registry bonding lands |
| `heartbeat_interval_sec` | 60 | `{load, clients, version, uptime}` tick |
| `mgmt_bind` | `127.0.0.1:18081` | loopback unless `allow_remote=true` |
| `wg_interface/listen_port/address` | `veilnet0/51820/100.64.0.1` | server gateway |
| `wg_private_key` | — | base64, `0600`, never leaves the box |
| `cgnat_cidr` | `100.64.0.0/10` | per-client `/32` leases |
| `abuse_contact/jurisdiction` | — | required for `EXIT` |
| `allowed_ports/denied_ports/default_allow` | deny 25 only | outbound port policy |
| `rate_limit_kbps/rate_burst_kb` | 0 = unlimited | accounting-level budget |
| `max_session_minutes` | 480 | caps every session lifetime |
| `emergency_disable` | false | runtime kill switch (`503` on authorize) |
| `dev_allow_any` | false | dev tokens; **never** in production |

## 3. Open the network path

The node needs inbound UDP on your WireGuard port, plus forwarding and NAT.

```powershell
# Windows (admin)
netsh advfirewall firewall add rule name="veilnet-in" dir=in action=allow protocol=UDP localport=51820
# then enable IPEnableRouter + NAT (ICS or New-NetNat)
```

```bash
# Linux
sysctl -w net.ipv4.ip_forward=1
iptables -A FORWARD -i veilnet0 -j ACCEPT
iptables -A FORWARD -o veilnet0 -j ACCEPT
iptables -t nat -A POSTROUTING -s 100.64.0.0/10 -j MASQUERADE
```

`run` applies the Linux path best-effort and prints the dry-run commands on
other platforms. Without privileges or WireGuard the daemon still runs
degraded (in-memory peer table) so config and API stay testable.

## 4. Run it

```powershell
.\dist\veilnet-node.exe run
.\dist\veilnet-node.exe status     # live status screen
```

Other commands:

```powershell
veilnet-node rotate-keys                       # new WireGuard identity, prints the pubkey to re-register
veilnet-node report-abuse --reporter R --reason R [--action A] [--ip IP]
veilnet-node blocklist list|block-ip|unblock-ip|block-key|unblock-key [VALUE]
veilnet-node run --abuse-autodisable --abuse-threshold 5
```

`run --dev` accepts unsigned tokens. It is for local testing only — never
production.

## 5. Control API

Loopback only, bearer token from `~/.veilnet-node/mgmt.token`. Every route
needs `Authorization: Bearer <token>`.

| Method + path | Meaning |
| ------------- | ------- |
| `GET /health` | node id, type, region, version, uptime, clients |
| `GET /capacity` | clients, max clients, accepting new |
| `GET /stats` | clients, rx/tx bytes, sessions today, uptime, DERO earned, load |
| `POST /session/authorize` | validates the token, installs the WireGuard peer, returns the assigned IP |
| `POST /session/revoke` | removes the peer, frees the IP |

Non-loopback callers get `403` unless `allow_remote=true` **and**
`mgmt_bind` is non-loopback. Expired token → `401`. At capacity → `429`.
Disabled or draining → `503`.

## 6. Operating safely

- Run the daemon as a dedicated low-privilege user. Only firewall and NAT
  setup needs elevation.
- Keep `mgmt_bind` on loopback. Rotate the token by deleting
  `mgmt.token` and restarting.
- `emergency_disable = true` stops new sessions instantly. Existing
  sessions can be cut with `POST /session/revoke`.
- **Never logged:** traffic content, DNS names, URLs, per-flow sizes.
- **Retained** in `clients.db` (accounting minimum): token/session/node
  ids, client WireGuard pubkey, assigned `/32`, endpoint, timestamps,
  revocation flag, aggregate byte counters, daily session count, lifetime
  earnings. Stop the daemon and delete `clients.db` to wipe it.

Deeper detail: `docs/NODE_OPERATOR.md`.

---

# Troubleshooting

The UI names the cause **and** the fix for every failure. Codes:

| Code | Means | Fix |
| ---- | ----- | --- |
| `service-down` | the privileged service is not reachable | install and start it: `.\scripts\install-service.ps1` then `sc.exe start VeilNetService` |
| `no-nodes` | no usable exits answered | try demo mode, pick another region, or check the registry/devnet is up |
| `wallet-unreachable` | the wallet did not answer | open your DERO wallet; enable XSWD, or start the wallet RPC server and check endpoint + login |
| `wallet-denied` | your wallet refused | nothing was spent — approve VeilNet in the wallet window and retry |
| `auth-rejected` | the node refused authorization | disconnect, restart the service to refresh credentials, reconnect |
| `payment-declined` | approval missing or over cap | nothing was spent — review the amount on Payment and approve explicitly |
| `dns-blocked` | name resolution blocked | set DNS mode to VeilNet in Settings, re-check Diagnostics |
| `tunnel-failed` | the encrypted tunnel did not come up | retry, auto-select the fastest node, or allow UDP through your firewall |

Still stuck: **Diagnostics → Refresh → Copy JSON**, and run
`.\dist\veilnet.exe --setup`.

---

## Arch

```text
cmd/veilnet            client app entry point (--demo supported)
cmd/veilnet-node       node operator entry point (run|status|init-config)
cmd/veilnet-service    privileged service (IPC host)
internal/tunnel        TunnelEngine: Start/Stop/Status/Statistics/
                       ApplyConfiguration/RotateEndpoint (DOWN/CONNECTING/UP/FAILED)
internal/wireguard     WireGuard device management + wgconf render
internal/routing       secure routes
internal/firewall      kill switch (OFF / ON_WHILE_CONNECTED / ALWAYS_ON)
internal/dns           DNS modes (VEILNET / CUSTOM / DOH / SYSTEM-explicit)
internal/dero          DERO control-plane client (RPC auth, XSWD bridge, DevMock)
internal/registry      node metadata + Sign/Verify + Select
internal/payments      explicit-approval payments + receipts/settlement
internal/session       authorized sessions (heartbeat/expiry)
internal/tokens        single-use auth tokens (+ session mapping)
internal/nodes         node operator stack (controller, heartbeat, IPAM)
internal/multihop      circuits (1-hop now; 3-hop builder in progress)
internal/storage       SQLite persistence
internal/security      IPC auth, ACLs, redaction, diagnostics
internal/ipc           named pipe \\.\pipe\veilnet-service (Windows) /
                       127.0.0.1 TCP fallback; token ~/.veilnet/service.token
internal/config        TOML (~/.veilnet/config.toml client,
                       ~/.veilnet-node/config.toml node)
internal/events        process bus: NODE_* TUNNEL_* KILL_SWITCH_ENABLED
                       DNS_CHANGED PAYMENT_* SESSION_* NODE_HEARTBEAT
                       CIRCUIT_ROTATED DERO_* ERROR
internal/ui            Wails v2 backend (vanilla HTML/CSS/JS, no npm step)
internal/contracts     shared shapes + veilnet.bas
```

Import note: WireGuard control imports as
`golang.zx2c4.com/wireguard/wgctrl` (+ `/wgtypes`) — the `wgctrl-go` path
does not exist.

## Dev

```powershell
pwsh scripts/devnet-up.ps1     # nodeA/B/C + test-server + dero-mock (devnet only)
go test ./tests/ ./tests/security/ -count=1
go test ./tests/integration/ -count=1 -v   # needs devnet fixtures; else SKIP=unverified
pwsh scripts/devnet-down.ps1
```

See `docs/DEVNET.md` (topology + mainnet separation), `docs/TESTING.md`
(suites + leak-test honesty contract), `deploy/docker-compose.yml`.

## Limitations (honest)

- **Kernel WireGuard is probed, not tuned.** Windows WireGuardNT and the
  Linux module are used when present, with userspace fallback; the active
  backend is named in tunnel status. Throughput is functional, not
  optimised.
- **Multi-hop (1–3) is live but young.** Builder, guard pinning, per-hop
  tokens and per-hop quotes are wired end-to-end and exercised against
  demo nodes. Real anonymity sets depend on operator adoption. **No
  global-passive-adversary protection is claimed, ever.**
- **Cover traffic is off by default and narrow.** `PAD` hides packet
  sizes; `CONSTANT` hides size and timing while the link keeps up.
  Neither defeats a global observer. Costs are measured, not hidden.
- **No obfuscating transport ships.** `internal/transport` is the seam
  and `direct` (plain UDP) is the only registered transport. An unknown
  transport name is a hard startup error, never a quiet fallback.
- **Prepaid billing is verified against DevMock only.** Do NOT run
  mainnet billing on this build. No external audit yet.
- **Mobile is a library, not an app.** The gomobile API and the OS
  VPN-permission handshake are implemented and unit-tested; on-device
  validation, background-service behaviour and battery are open work.
- **Installers:** `.\scripts\package.ps1` builds a versioned `.zip`
  always, and an MSI when WiX v3 is installed and the version is a
  numeric `MAJOR.MINOR.PATCH`.
- Exit nodes carry real legal exposure — read `docs/SECURITY.md` first.
- Full ledger: `docs/CURRENT_LIMITATIONS.md`.

## Roadmap

- **v1 — done:** single-hop VPN, DERO control plane, client + service +
  IPC, kill switch, DNS modes, IPv6 route-or-block.
- **v1.1 — done:** kernel WireGuard probes, audited token/billing paths,
  packaging (zip/MSI/deb/rpm), exit-operator abuse tooling, and
  service-enforced leak protection (rules applied on Connect, restored on
  Disconnect, fail-closed on error).
- **v2 — done:** multi-hop ≤3 hops, entry-guard pinning, per-hop layered
  tokens, per-hop pro-rata quotes under one approval.
- **v2.1 — in progress:** cover-traffic shaping (`internal/cover`,
  measured, off by default) and the pluggable entry-transport seam
  (`internal/transport`). Bridge transports themselves are not written.
- **v3 — beta:** decentralized reputation, mobile library with OS
  VPN-permission wiring, third-party SDK with a conformance suite.
- Non-goals: traffic inspection, telemetry, custodial/auto-spend wallets,
  user traffic over DERO (control plane only, forever).

Details: `docs/ROADMAP.md`. Security model: `docs/SECURITY.md`.
Install detail: `docs/INSTALL.md`. Node detail: `docs/NODE_OPERATOR.md`.
Shaping and transports: `docs/SHAPING.md`.
