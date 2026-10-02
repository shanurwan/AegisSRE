$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path $PSScriptRoot 'e2e-k3s.py'
& python $scriptPath @args
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
