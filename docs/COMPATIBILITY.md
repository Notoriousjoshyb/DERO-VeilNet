# COMPATIBILITY — DERO // VEILNET

> Scope (CleanQA): cross-platform build + feature parity ledger. Every verdict
> below follows an actually-executed observation on the date shown. Anything
> marked UNTESTED is an honest non-result, never a pass. Gaps name an owner.

- Module: `go 1.22` (go.mod directive; host toolchain `go1.25.3 windows/amd64`).
- Method: `CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> go build -o <out> ./cmd/<bin>`.
- Binaries: `veilnet` (client CLI+GUI), `veilnet-service` (privileged tunnel
  service), `veilnet-node` (exit/entry node daemon).

## Build matrix

Executed 2026-09-06 on Windows 11 (go1.25.3), tree after PlatformCoreAgent
`go mod tidy` (Main-approved) and HardenAgent audit landings.

| Binary | Target | Verdict |
|---|---|---|
| veilnet | windows/amd64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-service | windows/amd64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-node | windows/amd64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet | linux/amd64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-service | linux/amd64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-node | linux/amd64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet | linux/arm64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-service | linux/arm64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-node | linux/arm64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet | darwin/amd64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-service | darwin/amd64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-node | darwin/amd64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet | darwin/arm64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-service | darwin/arm64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |
| veilnet-node | darwin/arm64 | PASS (CGO_ENABLED=0 go build, 2026-09-06) |

Notes:

- An earlier matrix run (same day, pre-tidy) showed transient failures from
  two real causes: (1) a missing `go.sum` entry for
  `golang.org/x/sync/errgroup` (via `github.com/mdlayher/socket`) that broke
  Linux builds importing the tunnel stack, and (2) mid-flight sibling edits
  in `internal/app`/`internal/session`. Both resolved before this matrix was
  recorded: `go mod tidy` (Main-approved) + landed edits. Kept on record so
  a regression of either signature is recognizable.
- `go vet` scoped, 2026-09-06: host `go vet` on
  `tests/platform + tests/onboarding + cmd/* + internal/platform +
  internal/firewall` clean; `GOOS=linux go vet` on
  `internal/platform + internal/firewall + internal/dns + internal/routing +
  internal/tunnel + cmd/veilnet` clean; `GOOS=darwin go vet` on
  `internal/platform + cmd/veilnet` clean. Repo-wide vet is Main's
  post-land validation, not recorded here.

## Executed runtime (beyond compile)

| Check | Where | Verdict |
|---|---|---|
| `veilnet --demo --status` exit 0, `Demo=true`, `EngineState=DOWN` | windows/amd64 host | PASS (journey test, 2026-09-06) |
| `veilnet --demo --connect demo-eu-01` reaches `state=UP` | windows/amd64 host | PASS (journey test, 2026-09-06) |
| `veilnet --demo --status` exit 0, DOWN | WSL Ubuntu 24.04, linux/amd64 binary | PASS (WSL run, 2026-09-06) |
| First run materializes fail-closed default config | windows host + WSL linux | PASS (journey test + WSL run, 2026-09-06) |
| `setup.sh` distro mapping (9 fixtures) + manager precedence + package/install-cmd shape + `--check` report | windows host via bash | PASS (platform suite, 2026-09-06) |
| Backend probes: exactly one Supported per kind on host | windows/amd64 host | PASS (platform suite, 2026-09-06) |
| darwin/arm64 runtime (status/connect/UI) | no macOS runner | UNTESTED (needs CI runner; owner Main) |
## Feature parity

| Feature | Windows 11 | Ubuntu/Debian/Fedora/RHEL/Arch/openSUSE | macOS |
|---|---|---|---|
| Tunnel (userspace WireGuard) | Demo connect UP executed 2026-09-06; kernel fast paths planned | Cross-compiles (all PASS 2026-09-06); live run only via WSL status check | Cross-compiles (all PASS 2026-09-06); runtime UNTESTED |
| Kill-switch | Config-state executed; `netsh` backend registered + Supported executed; live enforcement needs devnet fixtures (integration SKIPs without them) | `nftables` backend registered; Supported only on linux (needs linux runner for live proof) | `pf` backend registered; Supported only on darwin (needs macOS runner) |
| DNS | `netsh-nrpt` registered + Supported executed; enforcement via service (pending wiring, CURRENT_LIMITATIONS) | `systemd-resolved` registered; live proof needs runner | `networksetup` registered; live proof needs runner |
| IPv6 | Default no-upstream executed (config); block enforcement via routing backend, live per-OS UNTESTED | Same default; enforcement UNTESTED live | Same default; enforcement UNTESTED live |
| Privileged service | SCM spec + `sc` install hint executed | systemd units `deploy/packaging/veilnet.service`, `veilnet-node.service` present; install hint references systemctl (executed as string, not as install) | launchd plists `deploy/packaging/com.veilnet.service.plist`, `com.veilnet.node.plist` present; install hint references launchctl (string only) |
| Packaging | — | `setup.sh` detection executed for apt/dnf/yum/pacman/zypper/apk/brew; `deploy/packaging/rpm/veilnet.spec` present | `brew` package list executed; `deploy/packaging/wix/veilnet.wxs` present (MSI needs WiX toolchain; owner PackAgent) |
| Onboarding | First-run defaults + guided approval path executed (journey suite) | `--check` report contract executed; full guided flow needs distro runners | UNTESTED (needs runner) |
| Mobile (iOS/Android) | — | — | Constraints documented by mobile owner, not verified here (owner ReputationAgent) |

## Limitations

Unavoidable limitations (real, not footnotes):

- Leak protection is config-state until service wiring lands
  (`docs/CURRENT_LIMITATIONS.md`); no test claims live enforcement.
- iOS/Android tunnel constraints (always-on VPN APIs, per-app VPN
  entitlements, background execution) are owned and documented by the
  mobile owner; this ledger does not speak for those platforms.
- Silent-leak behavior on a new OS stays a release blocker, never a
  known-issue footnote (per CURRENT_LIMITATIONS platform section).

## Reproduce

```powershell
# Build matrix (15 cells)
foreach ($os in "windows","linux","darwin") {
  foreach ($arch in "amd64","arm64") {
    if ($os -eq "windows" -and $arch -eq "arm64") { continue }
    foreach ($c in "veilnet","veilnet-service","veilnet-node") {
      $env:CGO_ENABLED="0"; $env:GOOS=$os; $env:GOARCH=$arch
      go build -o "$env:TEMP/vmatrix/$c-$os-$arch" ./cmd/$c
    }
  }
}
$env:GOOS=""; $env:GOARCH=""; $env:CGO_ENABLED=""

# Suites owned by this ledger
go test ./tests/platform/ ./tests/onboarding/ ./tests/compat/ -count=1
```

## Gaps (hub-filed to Main)

- CI runners for linux/darwin/arm64 runtime (status/connect/service
  install): still open — needs hosted runners beyond this Windows box.
- ~~`platform.KindNAT` zero backends~~ resolved: dead kind removed; node NAT
  stays an explicit operator command list (`veilnet-node`, iptables/nft
  executed on Linux, dry-run elsewhere).
- Mobile tunnel constraints: documented as open work in docs/MOBILE.md
  (on-device validation, background service, OS VPN-permission wiring).
- MSI: `deploy/packaging/wix/veilnet.wxs` + docs/PACKAGING.md fallback (zip)
  present; a WiX-toolchain build is still unrun on this box.
- HardenAgent renames consumed here: payments chain
  `RecordSettlementIdem(node_id,total,count,batch_id)`,
  `Settlement.ID = stl-<hex64>`, node 429-class abuse surface
  (`--abuse-autodisable/--abuse-threshold`, `rotate-keys`,
  `report-abuse`, `blocklist`) — asserted via node `--help` in the
  journey suite; chain-call conformance stays with payments tests.
