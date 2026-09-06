# VeilNet onboarding

Zero-friction path from install to protected tunnel. No manual config
editing in any critical flow; sane defaults carry a fresh install.

## First run (zero config)

Starting the client with no `~/.veilnet/config.toml` just works:

1. Defaults load: `FASTEST` selection policy, `VEILNET` DNS,
   kill switch `ON_WHILE_CONNECTED`, devnet off (explicit `mainnet`).
2. The default file is auto-created on disk, so the next run is identical.
3. No wallet needed: demo and unpaid (`price 0`) dev nodes connect
   wallet-free. Paid nodes open an explicit approval dialog showing the
   real node id and DERO/hour — VeilNet never auto-spends, never fails
   silently.

Paid-node CLI notice: `veilnet --connect` prints the approval prompt to
stderr (`approval: Node <id> costs <x> DERO/hour ...`) and continues to
connect; the spend itself still requires explicit approval in the Payment
flow.

## GUI wizard (Get started)

The `Get started` screen walks five steps, skipped after the first
completion (stored in browser local storage, per machine):

1. **Welcome** — what the tour does, no config files involved.
2. **How it works** — three bullets: DERO control plane (discovery,
   authorization, payments only, never traffic), WireGuard data plane
   (encrypted device-to-exit tunnel), explicit approval for every payment.
3. **Speed & region** — policy (`FASTEST` default) plus optional region,
   saved through the normal config API (secrets stay redacted server-side).
4. **Connect** — auto-picks the fastest known-latency node; paid nodes
   pop a native confirm dialog with the real price before connecting.
5. **Done** — names the exit node; protection holds while the status pill
   reads `PROTECTED` (engine `UP`, never a badge without it).

## CLI

- `veilnet --setup` — environment report: OS/arch, admin state, config
  validity, service token + reachability, state-db presence, DERO RPC
  reachability, wallet-optional note. Every failure line is prefixed
  `[FIX]` with the concrete command or file to touch. Exit code is
  always 0; it never edits anything.
- `veilnet --demo --connect [id]` — zero-config demo connect (auto-picks
  the fastest seed when `id` is omitted), live stats loop.
- First-run notices go to stderr: config auto-created path, unclean-exit
  reconnect prompt, `ALWAYS_ON` sentinel reminder, wallet-optional note.

## Error catalog

Every user-facing failure maps to a code plus cause plus fix, in CLI
stderr (`veilnet [<code>]: <cause> Fix: <fix>`) and in the GUI error
banner (same codes, see `internal/ui/frontend/wizard.js`):

| code | cause | fix |
|---|---|---|
| `service-down` | privileged service unreachable, no tunnel possible | start it: per-OS one-command hint (`ServiceInstallHint`) |
| `no-nodes` | discovery returned no usable exits | try `--demo`, another region, or check registry/devnet |
| `auth-rejected` | node rejected session authorization | disconnect, restart service to refresh credentials, reconnect |
| `payment-declined` | declined or still needs approval; nothing spent | review amount in Payment screen, approve explicitly |
| `tunnel-failed` | encrypted tunnel / handshake failed | retry, auto-select fastest, allow UDP through firewall |
| `dns-blocked` | resolution blocked by DNS posture | set DNS mode `VEILNET`, re-check Diagnostics |
| `connect-failed` | anything else (keeps original text) | open Diagnostics, run `veilnet --setup` |

## Crash-safe state

- A `veilnet.clean_exit` setting marks the run dirty at startup and clean
  on disconnect/shutdown. A dirty flag at startup surfaces the
  "did not exit cleanly; reconnect" prompt instead of pretending all is
  well.
- `ALWAYS_ON` killswitch is a sentinel: configured means respected even
  while disconnected; the notice names it on every start.
- Settings, node history, latency samples, trust scores, connection
  history, and payment receipts live in SQLite (`~/.veilnet/client.db`)
  plus the TOML config — all survive restarts (proven by
  `TestOnboardingJourney` in `internal/app/onboard_test.go`).

## Missing pieces name their fix

- Missing service: the error carries the exact per-OS install command
  (Windows elevated `install-service.ps1`; Linux/macOS `setup.sh` plus
  elevated service start) instead of "connection refused".
- Missing/invalid config: invalid files report the offending value;
  deleting the file restores safe defaults.
- Missing wallet: wallet-optional note, not an error — only paid flows
  ask, and they ask explicitly.

## Privacy invariants (onboarding honors them)

- No analytics/telemetry/traffic logging anywhere in these flows.
- DERO carries control messages and payments only, never user traffic.
- Config API echoes secrets redacted (`***`); empty secret fields keep
  stored values rather than wiping them.
