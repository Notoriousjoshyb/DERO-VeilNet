# VeilNet Node Operator Guide

Run a VeilNet exit or relay node on Windows 11 first, Linux/macOS portable.
No custom crypto. DERO never carries user traffic; secret keys never go on-chain.

## Node types (explicit)

| Type | Meaning |
| ---- | ------- |
| `EXIT` | Client traffic leaves to the public internet from this node. Requires abuse contact + jurisdiction. |
| `RELAY` | Multihop middle only: forwards encrypted tunnels, never exits. Exit-scoped tokens are rejected (`ErrRelayScope`). |

`node_type` in `~/.veilnet-node/config.toml` must be `EXIT` or `RELAY`. It is
printed in `status`, `/health`, `/stats`, and heartbeats — never inferred.

## Quick start

```powershell
veilnet-node init-config
# edit ~/.veilnet-node/config.toml: region/country/city, max_clients,
# price_per_hour_dero, public_endpoint, dero_address, abuse_contact
veilnet-node run
veilnet-node status
```

Linux/macOS: same commands; config at `~/.veilnet-node/config.toml`.

## Config reference (`~/.veilnet-node/config.toml`)

| Key | Default | Notes |
| --- | ------- | ----- |
| `node_type` | `EXIT` | `EXIT` or `RELAY` |
| `region/country/city` | local/dev | advertised metadata |
| `max_clients` | 50 | capacity; authorize past this → `429` |
| `bandwidth_down/up_mbps` | 100/100 | advertised + status display |
| `price_per_hour_dero` | 0.01 | never auto-spent; client approves each payment |
| `accept_new` | true | `false` drains the node (authorize → `503`) |
| `public_endpoint` | — | `ip:port` clients dial |
| `dero_address` | — | payouts (public address only) |
| `bond_dero` | 0 | informational until registry bonding lands |
| `heartbeat_interval_sec` | 60 | `{load, clients, version, uptime}` tick |
| `mgmt_bind` | `127.0.0.1:18081` | loopback only unless `allow_remote=true` |
| `wg_interface/listen_port/address` | `veilnet0/51820/100.64.0.1` | server `/10` gateway |
| `wg_private_key` | — | base64, `0600`, never leaves the box |
| `cgnat_cidr` | `100.64.0.0/10` | per-client `/32` leases |
| `abuse_contact/jurisdiction` | — | required for EXIT |
| `allowed_ports/denied_ports/default_allow` | deny 25 only | outbound port policy |
| `rate_limit_kbps/rate_burst_kb` | 0 = unlimited | accounting-level budget |
| `max_session_minutes` | 480 | caps every session lifetime |
| `emergency_disable` | false | runtime kill switch (`503` on authorize) |
| `dev_allow_any` | false | dev tokens; never in production |

## Control API (127.0.0.1 only, bearer token)

Token file `~/.veilnet-node/mgmt.token` (32 random bytes hex, `0600`).
Every route needs `Authorization: Bearer <token>`.

| Method+Path | Meaning |
| ----------- | ------- |
| `GET /health` | `{status, node_id, node_type, region, version, uptime_sec, clients, max_clients}` |
| `GET /capacity` | `{clients, max_clients, accept_new}` |
| `GET /stats` | `{clients, rx/tx_bytes, sessions_today, uptime_sec, dero_earned, load}` |
| `POST /session/authorize` `{token, client_pubkey, endpoint}` | validates, enforces capacity/policy, installs WG peer → `{token_id, assigned_ip, expires_at}` |
| `POST /session/revoke` `{token_id}` | removes peer, frees IP |

Non-loopback peers get `403` unless `allow_remote=true` **and**
`mgmt_bind` is non-loopback; startup refuses a non-loopback bind without
the explicit flag. Expired tokens → `401`; at capacity → `429`;
disabled/draining → `503`.

## Session accounting

- Per-token `rx/tx_bytes` counters + `LastActivity`; time quota via
  `expires_at` (min of token expiry and `max_session_minutes`).
- A 30 s sweeper evicts expired sessions, revokes the token ID
  (single-use revocation map — reuse rejected), removes the WireGuard
  peer, and frees the `/32`.
- Revocation is permanent for the process lifetime.

## WireGuard hosting

- Peer add/remove via `wgctrl`; each client pinned to one `/32` from
  CGNAT with 25 s keepalive.
- Without privileges/WireGuard the daemon runs degraded (in-memory peer
  table) so config and API stay testable; production needs the real device:

```powershell
# Windows (admin): create veilnet0 via WireGuard, allow UDP 51820, enable routing
netsh advfirewall firewall add rule name="veilnet-in" dir=in action=allow protocol=UDP localport=51820
# Enable IPEnableRouter + NAT (ICS or New-NetNat), see firewall.go dry-run
```

```bash
# Linux
sysctl -w net.ipv4.ip_forward=1
iptables -A FORWARD -i veilnet0 -j ACCEPT
iptables -A FORWARD -o veilnet0 -j ACCEPT
iptables -t nat -A POSTROUTING -s 100.64.0.0/10 -j MASQUERADE
```

`run` applies the Linux path best-effort and prints the dry-run commands
on other platforms. Outbound port policy renders as `FORWARD` rules.

## Least privilege

- Run as a dedicated low-privilege user; only firewall/NAT setup needs elevation.
- Config + token DB are `0700` dirs, `0600` files. `wg_private_key` and
  `mgmt.token` never leave the host, never appear in logs, never go on-chain.
- Bind the control API to loopback; rotate `mgmt.token` by deleting it and restarting.
- `emergency_disable=true` (or the runtime toggle) stops new sessions
  instantly; existing sessions can be revoked via `/session/revoke`.

## Privacy: what is (and is not) logged

Never logged: traffic content, DNS names/queries, URLs, payload sizes
beyond aggregate counters. Console output is connect/disconnect events
and warnings only.

Retained (accounting minimum, `clients.db`):

- `token_id, session_id, node_id, scope`
- client WireGuard pubkey, assigned `/32`, endpoint `ip:port`
- `created_at, expires_at`, revocation flag
- aggregate `rx_bytes, tx_bytes` per token (no per-flow detail)
- per-day session counter, lifetime DERO earnings

Delete `clients.db` to wipe accounting (active leases are re-reserved
from it on startup, so stop the daemon first).
