#Requires -Version 5.1
<#
.SYNOPSIS
  Stop the VEILNET devnet and optionally wipe dev state.
.EXAMPLE
  pwsh scripts/devnet-down.ps1
  pwsh scripts/devnet-down.ps1 -Wipe
#>
param([switch]$Wipe)
$ErrorActionPreference = 'Stop'

$Repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $Repo

docker compose -f deploy/docker-compose.yml down
if ($LASTEXITCODE -ne 0) { Write-Error 'docker compose down failed.'; exit 1 }

if ($Wipe) {
  $DevDir = Join-Path $Repo '.veilnet-dev'
  if (Test-Path $DevDir) { Remove-Item -Recurse -Force $DevDir }
  Write-Host 'Devnet stopped; .veilnet-dev wiped.'
} else {
  Write-Host 'Devnet stopped; dev state kept in .veilnet-dev (use -Wipe to remove).'
}
