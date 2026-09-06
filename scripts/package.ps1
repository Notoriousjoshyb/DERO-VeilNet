#Requires -Version 5.1
<#
.SYNOPSIS
  Builds distributable VeilNet packages on Windows: an MSI when WiX v3 is
  present, and always a versioned .zip.
.DESCRIPTION
  Mirrors scripts/package.sh for the Windows host.

  Version comes from $env:VERSION, else dist\VERSION, else
  `git describe --tags --always --dirty`, else 0.1.0-dev.

  The MSI needs a numeric MAJOR.MINOR.PATCH ProductVersion. A
  non-numeric version (e.g. 0.1.0-dev, or a bare commit hash) cannot be
  stamped into an MSI, so the MSI step is skipped with a clear note and
  the .zip is produced instead. That is a real limitation of MSI, not a
  failure of this script.

  Missing WiX is likewise a skip, never an error:
    winget install -e --id WiXToolset.WiX      (v3 candle/light)
.EXAMPLE
  .\scripts\package.ps1
  .\scripts\package.ps1 -Format zip -Out release
  $env:VERSION='1.2.3'; .\scripts\package.ps1 -Format all
#>
param(
  [ValidateSet('all', 'msi', 'zip')]
  [string]$Format = 'all',
  [string]$Out = 'release',
  [switch]$NoBuild
)
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $here '..')

# ---------- version ----------

$version = $env:VERSION
if (-not $version -and (Test-Path 'dist\VERSION')) {
  $version = (Get-Content 'dist\VERSION' -Raw).Trim()
}
if (-not $version) {
  try { $version = (git describe --tags --always --dirty 2>$null) } catch { $version = '' }
}
if (-not $version) { $version = '0.1.0-dev' }
$version = $version.Trim()

# ---------- build ----------

if (-not $NoBuild) {
  $env:VERSION = $version
  & (Join-Path $here 'build.ps1')
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$required = @('dist\veilnet.exe', 'dist\veilnet-node.exe', 'dist\veilnet-service.exe')
foreach ($f in $required) {
  if (-not (Test-Path $f)) {
    Write-Error "Missing $f. Run .\scripts\build.ps1 first (or drop -NoBuild)."
    exit 1
  }
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$outFull = (Resolve-Path $Out).Path
$made = New-Object System.Collections.Generic.List[string]

# ---------- zip ----------

function New-Zip {
  $name = "veilnet-$version-windows-amd64.zip"
  $path = Join-Path $outFull $name
  $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("veilnet-pkg-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $stage | Out-Null
  try {
    foreach ($f in $required) { Copy-Item -Force $f $stage }
    foreach ($f in @('dist\wintun.dll', 'dist\VERSION', 'dist\BUILDINFO', 'README.md', 'LICENSE')) {
      if (Test-Path $f) { Copy-Item -Force $f $stage }
    }
    if (Test-Path $path) { Remove-Item -Force $path }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $path -CompressionLevel Optimal
    $made.Add($path)
    Write-Host "Packaged: $path"
  } finally {
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
  }
}

# ---------- msi ----------

function Find-WixTool([string]$exe) {
  $cmd = Get-Command $exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $roots = @(
    "$env:WIX\bin",
    "${env:ProgramFiles(x86)}\WiX Toolset v3.14\bin",
    "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin"
  )
  foreach ($r in $roots) {
    if ($r -and (Test-Path (Join-Path $r $exe))) { return (Join-Path $r $exe) }
  }
  return $null
}

function New-Msi {
  # MSI ProductVersion must be numeric MAJOR.MINOR.PATCH.
  if ($version -notmatch '^\d+\.\d+\.\d+$') {
    Write-Host "Skipping MSI: version '$version' is not numeric MAJOR.MINOR.PATCH."
    Write-Host "  Tag a release, or set `$env:VERSION='1.2.3' before packaging."
    return
  }
  $candle = Find-WixTool 'candle.exe'
  $light = Find-WixTool 'light.exe'
  if (-not $candle -or -not $light) {
    Write-Host "Skipping MSI: WiX v3 not found (candle.exe/light.exe)."
    Write-Host "  Install it with: winget install -e --id WiXToolset.WiX"
    return
  }

  $obj = Join-Path $outFull 'wixobj'
  New-Item -ItemType Directory -Force -Path $obj | Out-Null
  $wxs = 'deploy\packaging\wix\veilnet.wxs'
  $dist = (Resolve-Path 'dist').Path

  & $candle "-dProductVersion=$version" "-dDistDir=$dist" -out "$obj\" $wxs
  if ($LASTEXITCODE -ne 0) { Write-Error 'candle.exe failed'; exit $LASTEXITCODE }

  $msi = Join-Path $outFull "veilnet-$version-windows-amd64.msi"
  & $light -ext WixUtilExtension -out $msi (Join-Path $obj 'veilnet.wixobj')
  if ($LASTEXITCODE -ne 0) { Write-Error 'light.exe failed'; exit $LASTEXITCODE }

  Remove-Item -Recurse -Force $obj -ErrorAction SilentlyContinue
  $made.Add($msi)
  Write-Host "Packaged: $msi"
}

# ---------- run ----------

switch ($Format) {
  'zip' { New-Zip }
  'msi' { New-Msi }
  'all' { New-Zip; New-Msi }
}

if ($made.Count -eq 0) {
  Write-Host 'No packages produced.'
  exit 1
}

# ---------- checksums ----------

$sumFile = Join-Path $outFull "SHA256SUMS-$version.txt"
$lines = foreach ($p in $made) {
  $h = (Get-FileHash -Algorithm SHA256 -Path $p).Hash.ToLower()
  "$h  $([System.IO.Path]::GetFileName($p))"
}
Set-Content -Path $sumFile -Value $lines -Encoding utf8
Write-Host "Checksums: $sumFile"
$lines | ForEach-Object { Write-Host "  $_" }
