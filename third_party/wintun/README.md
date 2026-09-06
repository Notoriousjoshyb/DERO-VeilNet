# third_party/wintun — vendored Wintun driver (Windows userspace TUN)

The VeilNet Windows userspace backend (`internal/tunnel`, via
`golang.zx2c4.com/wireguard/tun`) loads `wintun.dll` from beside the
executable. Releases ship it in `dist/` (staged by `scripts/build.ps1`);
if it is absent the user needs a WireGuard install instead
(`scripts/setup.ps1 -Check` reports exactly which case applies).

## Provenance

- Upstream: https://www.wintun.net/builds/wintun-0.14.1.zip
- Zip SHA-256: 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
- Files kept: `bin/amd64/wintun.dll` → `wintun-amd64.dll`,
  `bin/arm64/wintun.dll` → `wintun-arm64.dll`, plus upstream `LICENSE.txt`.
- License: Wintun is distributed under its own license terms, see
  `LICENSE.txt`. It is a driver component, not VeilNet code.

## Updating

1. Download the new build from https://www.wintun.net/ (signed by the
   upstream publisher; verify the signature before vendoring).
2. Replace the two DLLs, update the SHA-256 above, and note the version
   in `docs/PACKAGING.md`.
