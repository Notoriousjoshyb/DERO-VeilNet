# VeilNet Packaging Notes (maintainers)

How we ship: reproducible tarballs everywhere, native packages where the
tooling exists, graceful documented fallbacks elsewhere. No Electron, no
custom crypto, no telemetry in any artifact.

## Versioning and reproducibility

- `VERSION` defaults to `git describe --tags --always --dirty`, falling back
  to `0.1.0-dev`. Override: `VERSION=1.2.3 ./scripts/build.sh`.
- `SOURCE_DATE_EPOCH` defaults to `git log -1 --format=%ct`, else now.
  Override for byte-identical rebuilds:
  `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) ./scripts/build.sh`.
- `scripts/build.sh` / `scripts/build.ps1` compile with
  `-trimpath -buildvcs=false` and write `dist/VERSION` + `dist/BUILDINFO`.
- `scripts/package.sh` normalizes archives on GNU tar
- (`--sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH"`);
- on bsdtar (Git for Windows, some BSDs) it falls back to plain tar with a note.
- Per-binary `--version` ldflags stamping is intentionally absent: the CLIs
  have no `var buildVersion` hook (that file surface belongs to other owners).
  `dist/VERSION` is the stamped record until such a hook lands.

## Format matrix (`./scripts/package.sh --format all|tar|deb|rpm|zip|dmg`)

| Format | Tool required | Fallback when absent |
|---|---|---|
| `.tar.gz` | tar+gzip (always) | — (always built) |
| `.deb` | `dpkg-deb` | Skip with note (`sudo apt-get install -y dpkg-dev`) |
| `.rpm` | `rpmbuild` | Skip with note (`sudo dnf install -y rpm-build` / `sudo zypper install -y rpm-build`); `deploy/packaging/rpm/veilnet.spec` + the tarball is all a maintainer needs |
| `.zip` (Windows) | `zip`, or `Compress-Archive` on Windows | Printed `Compress-Archive` one-liner |
| `.dmg` (macOS) | `hdiutil` on a Mac | Printed `hdiutil create` command; never faked on Linux |
| MSI (Windows) | WiX (`candle.exe`/`light.exe`) | Zip fallback (below); never a fake MSI |

The `.deb` postinst enables `veilnet.service` (never the node unit — nodes
opt in). The `.rpm` uses the standard `%systemd_post` macros.

## Windows packaging (`.\scripts\package.ps1`)

The Windows counterpart to `package.sh`. It always produces a versioned
`.zip`, produces an MSI when it can, and writes `SHA256SUMS-<ver>.txt`.

```powershell
.\scripts\package.ps1                      # zip + MSI if possible
.\scripts\package.ps1 -Format zip           # zip only
$env:VERSION='1.2.3'; .\scripts\package.ps1 -Format msi -NoBuild
```

Two honest skips, each with the fix printed:

- **Non-numeric version.** An MSI `ProductVersion` must be
  `MAJOR.MINOR.PATCH`, so `0.1.0-dev` cannot be stamped. Tag a release or
  set `$env:VERSION`.
- **WiX absent.** `winget install -e --id WiXToolset.WiX`. The script
  searches `$env:WIXin` and the standard v3.11/v3.14 install paths
  before giving up.

Neither skip fails the zip, and neither ever produces a fake MSI.

## MSI via WiX (`deploy/packaging/wix/veilnet.wxs`)

WiX v3, per-machine, three components (client, node, service EXEs); the
service component registers `VeilNetService` (demand-start) via
`ServiceInstall`/`ServiceControl`. Build on Windows after `.\scripts\build.ps1`:

```powershell
candle.exe -dProductVersion=1.0.0 -dDistDir=dist -out obj\ wix\veilnet.wxs
light.exe -ext WixUtilExtension -out veilnet-1.0.0.msi obj\veilnet.wixobj
```

`ProductVersion` must be numeric `MAJOR.MINOR.PATCH`: derive it from
`dist\VERSION` (e.g. git tag `1.2.3`) via `-dProductVersion` or `$env:VERSION`
in CI. Without WiX: `Compress-Archive -Path dist\*.exe -DestinationPath
veilnet-<ver>-windows-amd64.zip` plus the elevated
`.\scripts\install-service.ps1` step from `docs/INSTALL.md`.

## Service files (`deploy/packaging/`)

- `veilnet.service` / `veilnet-node.service` (systemd): service is
  demand-persistent with `Restart=on-failure`; the node unit is installed but
  never auto-enabled by install scripts or packages.
- `com.veilnet.service.plist` / `com.veilnet.node.plist` (launchd):
  `RunAtLoad=false`, `KeepAlive` on unsuccessful exit only.
- `scripts/install.sh` rewrites the `/usr/local/bin` prefix in these files
  with `sed` when `--prefix`/`--bindir` differ; `scripts/uninstall.sh`
  reverses everything except config/state (needs `--purge`).

## Verification (scoped; no repo-wide suites here)

```sh
bash -n scripts/setup.sh scripts/build.sh scripts/install.sh scripts/uninstall.sh scripts/package.sh
bash deploy/packaging/tests/test_detect.sh
```

PowerShell (on Windows):

```powershell
$files = 'scripts\setup.ps1','scripts\build.ps1'
foreach ($f in $files) {
  $errs = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errs)
  if ($errs.Count -gt 0) { throw "$f : $($errs[0].Message)" } else { Write-Host "ok: $f" }
}
```

Every script must stay parse-clean; the detect test must stay green on all
fixtures in `deploy/packaging/tests/fixtures/`.
