#Requires -Version 5.1
<#
.SYNOPSIS
  Runs VeilNet tests, scoped to a package pattern.
.PARAMETER Packages
  Go package pattern, e.g. './internal/...', './internal/tunnel/...'.
  Defaults to './internal/...'. Each agent runs scoped checks inside its
  own dirs; repo-wide suites are the main agent's job at the end.
#>
param(
  [string]$Packages = './internal/...'
)

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $here '..')

$env:GOTOOLCHAIN = 'local'
go test $Packages
exit $LASTEXITCODE
