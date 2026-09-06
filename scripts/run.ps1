#Requires -Version 5.1
<#
.SYNOPSIS
  Runs VeilNet demo mode or the devnet stack.
.PARAMETER Target
  'demo' runs dist\veilnet.exe --demo (badged, isolated from prod state).
  'devnet' brings up deploy/ via docker compose (owned by DocsTestsDevnet).
#>
param(
  [ValidateSet('demo', 'devnet')]
  [string]$Target = 'demo'
)

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $here '..')

if ($Target -eq 'demo') {
  if (-not (Test-Path dist\veilnet.exe)) {
    Write-Host 'dist\veilnet.exe missing, building first...'
    & "$here\build.ps1"
  }
  & .\dist\veilnet.exe --demo
  exit $LASTEXITCODE
}

# devnet: compose stack lives in deploy/ (DocsTestsDevnet owns it).
if (-not (Test-Path deploy\docker-compose.yml)) {
  Write-Error 'deploy\docker-compose.yml not present yet (devnet stack lands with DocsTestsDevnet).'
  exit 1
}
docker compose -f deploy\docker-compose.yml up --build
