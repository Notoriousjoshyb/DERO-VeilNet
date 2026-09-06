# TESTING — DERO // VEILNET

> Scope (DocsTestsDevnet): how to run the suites in `tests/`. Test code lives
> only in `tests/*` (+ `deploy/` fixtures).

## Layout

| Path | Contents | Needs fixtures? |
|---|---|---|
| `tests/ref/` | Test-owned reference harness mirroring the binding Contract (NOT prod code) | no |
| `tests/*_test.go` | Conformance: engine, bus, tokens, selection, wgconf, billing, config, policy, session, multihop, store | no |
| `tests/security/` | Adversarial: forge, tamper, spoof, bypass, downgrade, leak-attempt | no |
| `tests/integration/` | Live CLIENT→NODE→TEST-SERVER: exit IP, DNS path, reconnect, killswitch | **yes (devnet)** |

The reference harness (`tests/ref`) exists because the swarm builds in
parallel: it pins the exact Contract semantics (state enums, event names,
token fields, scoring criteria, kill/DNS/IPv6 modes) so assertions are
meaningful now and re-wireable to `internal/*` later without editing tests.

## Run

```powershell
go test ./tests/ ./tests/security/ -count=1        # unit + adversarial
go test ./tests/integration/ -count=1 -v           # live (needs devnet)
```

Without fixtures, integration tests **SKIP as "unverified"** — that is an
honest non-result, never a pass. CI asserts the skip path too.

## Leak-test honesty contract

1. No test hardcodes PASS: every verdict follows a real observation
   (dial result, `/whoami` delta, stub answer, sweep outcome).
2. An observed leak FAILS loudly (`LEAK:` prefix in the message).
3. Missing fixtures SKIP with `unverified:` — counts as neither pass nor fail.
4. Decision logic (kill/DNS/IPv6 state machines) is unit-tested exhaustively;
   OS enforcement is integration-tested where fixtures allow.

## Fixtures (see `docs/DEVNET.md`)

| Env | Meaning |
|---|---|
| `VEILNET_DEVNET_SERVER` | test-server base URL |
| `VEILNET_TUNNEL_PROXY` | proxy egressing via the exit node |
| `VEILNET_TUNNEL_DNS` | DNS stub base URL (`/dns?name=`) |
| `VEILNET_NODE_CTL` | node control URL (`POST /bounce`) |
| `VEILNET_KILL_ARMED` | `1` = kill-switch live fixture armed |
| `VEILNET_PHYS_IFACE` | physical interface for forced-direct dials |

## Conformance notes (real impls vs `tests/ref`)

- `internal/tokens`: unknown-id and wrong-secret both fail closed as invalid
  (no id-validity oracle) — aligned with `ref` by agreement with
  DeroPayRegistry. Single-use revocation sticks past expiry in both.
- Selection tie-break is cheapest-first, lexicographic — same in both.
- `tests/persist_test.go` exercises the real `modernc.org/sqlite` driver
  (migrations, idempotency, crash durability, rollback atomicity);
  `tests/toml_test.go` exercises the real `BurntSushi/toml` driver
  (decode, safe defaults, malformed-input refusal).

## Platform matrix (CleanQA: `tests/platform`, `tests/onboarding`, `tests/compat`)

```powershell
go test ./tests/platform/ ./tests/onboarding/ ./tests/compat/ -count=1
```

| Suite | What it executes | Needs |
|---|---|---|
| `tests/platform` | `internal/platform` dirs/service/backend probes on the host OS; safe-default invariants; real `scripts/setup.sh` distro mapping (9 fixtures), manager precedence, package/install-cmd shape, `--check` report | bash (WSL or git-bash on Windows) for the setup.sh half; Go-only tests run anywhere |
| `tests/onboarding` | Clean-install journey in temp HOME: first-run `--demo --status`, real demo connect to `state=UP`, disconnect honesty, settings/state persistence across restarts, no stale firewall rules (stub runner), no leftover processes, node abuse-surface `--help` | builds `./cmd/veilnet` + `./cmd/veilnet-node` (skips honestly if the tree is mid-flight) |
| `tests/compat` | `docs/COMPATIBILITY.md` structure: every binary x every target present, every PASS carries in-row evidence + date, go directive match, cmd inventory | the doc itself |

Shell-execution note (Windows): the `bash` on PATH may be the WSL launcher,
which mangles `$` constructs in `bash -c` strings and drops custom Windows
env vars. The platform suite therefore delivers scripts via temp files with
variables assigned inline — no `bash -c` `$`, no ambient-PATH dependence.
Manager precedence additionally shadows `command -v` via `$FAKE_HAVE` so
WSL images (real apt-get) and dev boxes (brew) give identical results.

Cross-OS honesty: host rows execute for real; other-OS runtime rows need
that OS's runner (see `docs/COMPATIBILITY.md` UNTESTED entries, owner Main).
Missing fixtures/runners SKIP as `unverified` per the leak-test contract —
never a pass.
