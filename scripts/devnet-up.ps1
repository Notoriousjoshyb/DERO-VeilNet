#Requires -Version 5.1
<#
.SYNOPSIS
  Start the VEILNET devnet (nodeA/B/C + test-server + dero-mock). DEV ONLY.
.DESCRIPTION
  Creates .veilnet-dev (dev state directory, never ~/.veilnet), refuses any
  mainnet flag/env, brings up deploy/docker-compose.yml, waits for health,
  then prints the fixture env consumed by tests/integration.
.EXAMPLE
  pwsh scripts/devnet-up.ps1
#>
$ErrorActionPreference = 'Stop'

$Repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $Repo

foreach ($v in @('MAINNET', 'VEILNET_MAINNET')) {
  if ([Environment]::GetEnvironmentVariable($v) -eq '1') {
    Write-Error "FATAL: $v=1 set — refusing to start devnet near mainnet."
    exit 1
  }
}
foreach ($a in $args) {
  if ($a -match 'mainnet|Mainnet|MAINNET') {
    Write-Error "FATAL: mainnet argument refused in devnet script: $a"
    exit 1
  }
}

$DevDir = Join-Path $Repo '.veilnet-dev'
foreach ($d in @('nodeA', 'nodeB', 'nodeC', 'dero-mock')) {
  New-Item -ItemType Directory -Force -Path (Join-Path $DevDir $d) | Out-Null
}

$env:VEILNET_NETWORK = 'devnet'
docker compose -f deploy/docker-compose.yml up -d --build
if ($LASTEXITCODE -ne 0) { Write-Error 'docker compose up failed.'; exit 1 }

# Wait for observation + mock endpoints.
$deadline = (Get-Date).AddSeconds(90)
foreach ($url in @('http://127.0.0.1:18080/health', 'http://127.0.0.1:18091/health')) {
  while ($true) {
    try { Invoke-RestMethod -Uri $url -TimeoutSec 3 | Out-Null; break }
    catch {
      if ((Get-Date) -gt $deadline) { Write-Error "devnet health timeout: $url"; exit 1 }
      Start-Sleep -Seconds 2
    }
  }
}

Write-Host ''
Write-Host 'VEILNET devnet is up (DEVNET ONLY — never mainnet).'
Write-Host 'Export these fixtures, then run the integration suite:'
Write-Host ''
Write-Host '  $env:VEILNET_DEVNET_SERVER = "http://127.0.0.1:18080"'
Write-Host '  $env:VEILNET_TUNNEL_PROXY  = "http://127.0.0.1:18101"  # via nodeA control/proxy when implemented'
Write-Host '  $env:VEILNET_TUNNEL_DNS    = "http://127.0.0.1:18080"  # stub /dns on test-server'
Write-Host '  $env:VEILNET_NODE_CTL      = "http://127.0.0.1:18101"'
Write-Host '  go test ./tests/integration/ -v'
Write-Host ''
Write-Host 'Without the tunnel fixtures the integration tests SKIP as'
Write-Host '"unverified" — that is honest, never a pass.'
