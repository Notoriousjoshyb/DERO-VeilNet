#Requires -Version 5.1
<#
.SYNOPSIS
  VeilNet Windows dev setup: verifies the Go toolchain and downloads module deps.
.DESCRIPTION
  Fresh-clone entry point. Verifies Go >= 1.22, then populates the module
  cache from go.mod/go.sum. Also reports on WireGuard (tunnel bring-up) and
  WiX (optional, only needed to build the MSI). Never touches internal/*
  implementations.

  .\scripts\setup.ps1            # check + go mod download (safe default)
  .\scripts\setup.ps1 -Check     # prerequisite check only (onboarding hook)
  .\scripts\setup.ps1 -Install   # print (and with -Yes, run) winget/choco installs
.PARAMETER Check
  Prerequisite-check mode: prints ok:/missing: lines, exits 0 when every
  required prerequisite is present, 1 otherwise. No side effects.
.PARAMETER Install
  Offer the winget/choco install commands for what is missing.
.PARAMETER Yes
  With -Install, run the installers without prompting.
#>
[CmdletBinding()]
param(
  [switch]$Check,
  [switch]$Install,
  [switch]$Yes
)
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $here '..')

function Test-GoVersion {
  $go = Get-Command go -ErrorAction SilentlyContinue
  if (-not $go) { return $null }
  $verOut = (go version) | Select-Object -First 1
  if ($verOut -notmatch 'go(\d+)\.(\d+)') { return $null }
  $have = [Version]"$($Matches[1]).$($Matches[2]).0"
  if ($have -lt [Version]'1.22.0') { return $null }
  return $verOut
}

function Get-PackageManager {
  # Returns 'winget', 'choco', 'both', or 'none'.
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  $choco = Get-Command choco -ErrorAction SilentlyContinue
  if ($winget -and $choco) { return 'both' }
  if ($winget) { return 'winget' }
  if ($choco) { return 'choco' }
  return 'none'
}

function Find-BundledWintun {
  # Returns the wintun.dll path when a release-bundled driver is present:
  # beside this script, in dist/, beside an installed exe, or system32.
  # $null otherwise. Releases ship it; repo checkouts vendor it under
  # third_party/wintun/ (copied to dist/ by build/package scripts).
  $cands = @()
  if ($PSScriptRoot) {
    $cands += (Join-Path $PSScriptRoot 'wintun.dll')
    $cands += (Join-Path $PSScriptRoot '..\dist\wintun.dll')
    $cands += (Join-Path $PSScriptRoot '..\third_party\wintun\wintun-amd64.dll')
  }
  $cands += (Join-Path ([Environment]::GetFolderPath('System')) 'wintun.dll')
  $pf = ${env:ProgramFiles}; if ($pf) { $cands += (Join-Path $pf 'VeilNet\wintun.dll') }
  foreach ($c in $cands) {
    if ($c -and (Test-Path $c -PathType Leaf)) { return $c }
  }
  return $null
}

function Test-Prereqs {
  # Prints ok:/missing: lines; returns $true when required items are present.
  # WiX is optional (MSI packaging only) and never fails the check.
  $ok = $true

  $goVer = Test-GoVersion
  if ($goVer) { Write-Host "ok: go $goVer" }
  else {
    Write-Host 'missing: go (>= 1.22) -- install Go 1.22+ from https://go.dev/dl/'
    $ok = $false
  }

  $wg = Get-Command wg -ErrorAction SilentlyContinue
  $wintun = Find-BundledWintun
  if ($wg) { Write-Host "ok: wireguard-tools ($($wg.Source))" }
  elseif ($wintun) { Write-Host "ok: wintun driver (bundled at $wintun) -- userspace tunnel ready, no WireGuard install needed" }
  else {
    Write-Host 'missing: WireGuard (wg.exe) or bundled wintun.dll -- tunnel bring-up needs one of them'
    $ok = $false
  }

  $wix = Get-Command candle -ErrorAction SilentlyContinue
  if (-not $wix) { $wix = Get-Command wix -ErrorAction SilentlyContinue }
  if ($wix) { Write-Host "ok: WiX ($($wix.Source)) [optional, MSI only]" }
  else { Write-Host 'note: WiX not found [optional] -- only needed to build the MSI installer' }

  return $ok
}

function Get-InstallHints {
  # Copy-paste install commands for what is missing, preferring winget.
  param([string]$Manager)
  $useWinget = ($Manager -eq 'winget') -or ($Manager -eq 'both')
  $lines = @()
  if (-not (Test-GoVersion)) {
    if ($useWinget) { $lines += 'winget install -e --id GoLang.Go' }
    else { $lines += 'choco install golang -y' }
  }
  if ((-not (Get-Command wg -ErrorAction SilentlyContinue)) -and (-not (Find-BundledWintun))) {
    if ($useWinget) { $lines += 'winget install -e --id WireGuard.WireGuard' }
    else { $lines += 'choco install wireguard -y' }
    $lines += '# alternative: releases ship wintun.dll beside veilnet.exe (no install needed)'
  }
  # WiX is optional: mention, never require.
  $wix = Get-Command candle -ErrorAction SilentlyContinue
  if (-not $wix) { $wix = Get-Command wix -ErrorAction SilentlyContinue }
  if (-not $wix) {
    if ($useWinget) { $lines += '# optional (MSI only): winget install -e --id FireGiant.WiX' }
    else { $lines += '# optional (MSI only): choco install wixtoolset -y' }
  }
  return $lines
}

if ($Check) {
  if (Test-Prereqs) { exit 0 } else { exit 1 }
}

$prereqsOk = Test-Prereqs
$mgr = Get-PackageManager
if (-not $prereqsOk) {
  if ($mgr -eq 'none') {
    Write-Host 'No winget/choco found. Install manually: https://go.dev/dl/ and https://www.wireguard.com/install/'
  }
  else {
    $hints = Get-InstallHints -Manager $mgr
    if ($hints.Count -gt 0) {
      Write-Host ''
      Write-Host "Install missing prerequisites ($mgr):"
      $hints | ForEach-Object { Write-Host "  $_" }
      if ($Install) {
        if (-not $Yes) {
          $ans = Read-Host 'Run these installers now? [y/N]'
          if ($ans -ne 'y' -and $ans -ne 'Y') { Write-Host 'Aborted. Nothing changed.'; exit 0 }
        }
        foreach ($cmd in $hints) {
          if ($cmd.StartsWith('#')) { continue }
          Write-Host "Running: $cmd"
          Invoke-Expression $cmd
          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        }
        Write-Host ''
        Write-Host 'Re-checking after install:'
        $prereqsOk = Test-Prereqs
      }
      else {
        Write-Host '  or re-run with: .\scripts\setup.ps1 -Install'
      }
    }
  }
}

$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
  Write-Error 'Go toolchain not found in PATH. Install Go 1.22+ from https://go.dev/dl/ and re-run.'
  exit 1
}

$verOut = (go version) | Select-Object -First 1
if ($verOut -notmatch 'go(\d+)\.(\d+)') {
  Write-Error "Could not parse Go version from: $verOut"
  exit 1
}
$have = [Version]"$($Matches[1]).$($Matches[2]).0"
if ($have -lt [Version]'1.22.0') {
  Write-Error "Go 1.22+ required, found $verOut."
  exit 1
}
Write-Host "Found: $verOut"

$env:GOTOOLCHAIN = 'local'
go mod download all
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host 'Setup complete. Next: .\scripts\build.ps1'
