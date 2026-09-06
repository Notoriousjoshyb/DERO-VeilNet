#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs (or reinstalls) the VeilNet privileged service via sc.exe.
.DESCRIPTION
  Must run from an elevated prompt. Registers service 'VeilNetService'
  pointing at dist\veilnet-service.exe. Build first with .\scripts\build.ps1.
#>
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $here '..')

$svcName = 'VeilNetService'
$binPath = Join-Path (Get-Location) 'dist\veilnet-service.exe'
if (-not (Test-Path $binPath)) {
  Write-Error "Missing $binPath. Run .\scripts\build.ps1 first."
  exit 1
}

$existing = sc.exe query $svcName 2>$null
if ($LASTEXITCODE -eq 0) {
  Write-Host "Stopping existing service '$svcName'..."
  sc.exe stop $svcName | Out-Null
  Start-Sleep -Seconds 2
  Write-Host "Deleting existing service '$svcName'..."
  sc.exe delete $svcName | Out-Null
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  Start-Sleep -Seconds 2
}

sc.exe create $svcName binPath= "`"$binPath`"" start= demand
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
sc.exe description $svcName 'VeilNet privileged service (WireGuard data plane host, IPC endpoint).' | Out-Null
sc.exe failure $svcName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

Write-Host "Service '$svcName' installed. Start it with: sc.exe start $svcName"
