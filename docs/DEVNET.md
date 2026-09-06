# DEVNET — DERO // VEILNET

> Scope (DocsTestsDevnet): local dev network. Testnet/devnet are strictly
> separated from mainnet — by construction, not by convention.

## Topology (`deploy/docker-compose.yml`)

Isolated `172.28.0.0/16` bridge, no host networking, all ports bound to
loopback:

- `nodeA` (172.28.1.11, eu-central, 0.01/h) — `127.0.0.1:51820/udp`, ctl `:18101`
- `nodeB` (172.28.1.12, us-east, 0.05/h) — `127.0.0.1:51821/udp`, ctl `:18102`
- `nodeC` (172.28.1.13, ap-southeast, 0.02/h) — `127.0.0.1:51822/udp`, ctl `:18103`
- `test-server` (172.28.1.20) — observation API `:18080`
- `dero-mock` (172.28.1.30) — fake chain `:18091`

## Separation guarantees

1. **State directories:** dev state lives in `.veilnet-dev/` (created by the
   up scripts). `~/.veilnet` is never mounted — prod state cannot mix.
2. **Network flag:** every container gets `VEILNET_NETWORK=devnet`. Images
   and both mock servers exit(1) without it.
3. **Mainnet refusal:** the node entrypoint and both up scripts abort on any
   `*mainnet*` argument or `MAINNET=1`/`VEILNET_MAINNET=1`.
4. **Worthless tokens:** every mock id carries a `DEV-` prefix; mock
   balances are infinite test credits that settle nowhere.

## Up / down

```powershell
pwsh scripts/devnet-up.ps1      # Windows 11
pwsh scripts/devnet-down.ps1    # stop (add -Wipe to remove .veilnet-dev)
```

```sh
bash scripts/devnet-up.sh
bash scripts/devnet-down.sh --wipe
```

The up script prints the exact fixture env for `tests/integration`.
Without tunnel fixtures, integration tests skip as "unverified".

## Observation API (test-server)

- `GET /whoami` → `{"ip": "<source>"}` — compare direct vs tunnel path.
- `GET /dns?name=X.veilnet.test` → stub answer proving the DNS path.
- `GET /health` → liveness.

## Mock chain (dero-mock)

- `GET /height`, `GET /balance`, `POST /approve` → `DEV-APPROVAL-*`,
  `POST /settle` → `DEV-RCPT-*`. Approval-split flow without value.
