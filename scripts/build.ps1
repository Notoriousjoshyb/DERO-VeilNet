#Requires -Version 5.1
<#
.SYNOPSIS
  Builds the VeilNet Windows binaries into dist/.
.DESCRIPTION
  Stamps dist\VERSION and dist\BUILDINFO from $env:VERSION (default:
  `git describe --tags --always --dirty`, else 0.1.0-dev) and
  $env:SOURCE_DATE_EPOCH (default: last commit timestamp, else now).
  Builds with -trimpath -buildvcs=false for reproducible output.
#>
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $here '..')

$env:GOTOOLCHAIN = 'local'
New-Item -ItemType Directory -Force -Path dist | Out-Null

$version = $env:VERSION
if (-not $version) {
  try { $version = (git describe --tags --always --dirty 2>$null) } catch { $version = '' }
  if (-not $version) { $version = '0.1.0-dev' }
}
$epoch = $env:SOURCE_DATE_EPOCH
if (-not $epoch) {
  try { $epoch = (git log -1 --format=%ct 2>$null) } catch { $epoch = '' }
  if (-not $epoch) {
    $epoch = [string][int][double]::Parse((Get-Date -UFormat %s))
  }
}
$env:SOURCE_DATE_EPOCH = $epoch

$env:GOFLAGS = '-trimpath'
go build -buildvcs=false -o dist\veilnet.exe ./cmd/veilnet
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go build -buildvcs=false -o dist\veilnet-node.exe ./cmd/veilnet-node
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go build -buildvcs=false -o dist\veilnet-service.exe ./cmd/veilnet-service
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -Force -Path third_party\wintun\wintun-amd64.dll -Destination dist\wintun.dll -ErrorAction SilentlyContinue
if (Test-Path dist\wintun.dll) { Write-Host 'Staged: dist\wintun.dll (bundled userspace TUN driver)' }
else { Write-Host 'Warning: third_party\wintun\wintun-amd64.dll missing -- tunnel needs WireGuard installed instead' }

Set-Content -NoNewline -Path dist\VERSION -Value "$version`n"
$goVer = (go version) -replace '^go version ([^ ]+).*', '$1'
Set-Content -Path dist\BUILDINFO -Value @(
  "version=$version",
  "source_date_epoch=$epoch",
  "go=$goVer"
)

Write-Host "Built: dist\veilnet.exe dist\veilnet-node.exe dist\veilnet-service.exe ($version, epoch $epoch)"
