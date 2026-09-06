# VeilNet mobile library (experimental)

`mobile/veilnet` drives the same `internal/app` control plane as desktop
— no forked tunnel or payments logic. The API is gomobile-shaped: every
exported function takes and returns **strings** (JSON envelopes
`{"ok":bool,"data":"...","error":"..."}`), and no exported struct
carries func/chan fields.

## API

| Function | Input | Envelope data |
|---|---|---|
| `GetVersion()` | — | `"0.1.0"` (plain string) |
| `Configure(json)` | `{"region","max_price_per_hour","quote_hours","allow_paid"}` | applied config |
| `SelectNode(region)` | `""` = default; else same-region cheapest | SDK Node |
| `Start(nodeID)` | `""` = auto-select | approved Quote |
| `Stop()` | — | `{"state":"down"}` (idempotent) |
| `Status()` | — | Status |
| `Diagnostics()` | — | Diagnostics |

Payment safety: `Start` on a priced node requires `allow_paid:true`
(plus caps) from `Configure`; otherwise it returns `ok:false` instead
of spending. Unknown regions fail clearly; unknown JSON config fields
are rejected.

## Binding

```sh
gomobile bind -o veilnet.aar github.com/dero-veilnet/veilnet/mobile/veilnet
gomobile bind -target=ios -o Veilnet.xcframework github.com/dero-veilnet/veilnet/mobile/veilnet
```

Kotlin:

```kotlin
val cfg = Veilnet.configure("""{"allow_paid":true}""")
// parse envelope JSON, check "ok", then:
val quote = Veilnet.start("")
```

Swift:

```swift
let cfg = Veilnet_Configure(#"{"allow_paid":true}"#)
let quote = Veilnet_Start("")
```

`mobile/android` and `mobile/ios` are thin bind-target shims (no logic).

## OS VPN permission and TUN handoff

A mobile app cannot open a TUN device itself; the OS owns it. The library
therefore refuses to `Start` until the host hands over a tunnel handle.
A mobile client must never report a connection it cannot actually carry.

| Call | Purpose |
| ---- | ------- |
| `RequestPermission(provider)` | returns the exact host-side steps for `"android-vpnservice"` or `"apple-packettunnel"`, plus current grant state. Never triggers an OS prompt — only your UI can. |
| `SetTunnelFD(fd)` | Android: hand over the descriptor from `VpnService.Builder.establish()`. A negative fd is refused. |
| `GrantTunnel("apple-packettunnel")` | iOS/macOS: declare the `NEPacketTunnelProvider` grant (no fd crosses the API). |
| `ClearTunnel()` | release the handle after `Stop()`, before closing the fd. Idempotent. |
| `PermissionStatus()` | read grant state without changing it. |

Demo mode is exempt: it carries no real traffic and is badged as demo.

Kotlin:

```kotlin
// 1. system VPN consent
VpnService.prepare(context)?.let { startActivityForResult(it, RC_VPN) }

// 2. build the tunnel and hand over the descriptor
val pfd = Builder().addAddress("10.89.0.2", 32)
    .addDnsServer("10.89.0.1").addRoute("0.0.0.0", 0).establish()
Veilnet.setTunnelFD(pfd.detachFd())

// 3. connect
Veilnet.start("")
```

Swift (inside `NEPacketTunnelProvider.startTunnel`):

```swift
Veilnet_GrantTunnel("apple-packettunnel")
let quote = Veilnet_Start("")
```

Every call returns the same string envelope: `{"ok":true,"data":"..."}`
or `{"ok":false,"error":"..."}`. A refused `Start` names the exact call
you still owe it.

## Maturity: experimental

String-envelope API, approval-gated paid connects, OS VPN-permission
gating, and demo-backed flows are tested (`go test ./mobile/...`, incl. a
reflection test that fails the build if the exported API drifts out of
gomobile-safe types). **Not yet validated on-device**;
background-service behavior and battery are open work.
