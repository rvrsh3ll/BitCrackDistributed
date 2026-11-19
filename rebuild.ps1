# Rebuild bitcrack-distributed. The repo root is derived from this script's
# location, so it works from any checkout (no hardcoded paths).
# Usage: .\rebuild.ps1 [-Configuration Release|Debug] [-Target bitcrack-distributed]
param(
    [string]$Configuration = "Release",
    [string]$Target = "bitcrack-distributed"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $RepoRoot "build_vs2022"

# Stop all running instances
Stop-Process -Name bitcrack-distributed -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

if (-not (Test-Path $BuildDir)) {
    Write-Host "No build_vs2022 directory - run build.bat first to configure the project." -ForegroundColor Yellow
    exit 1
}

# Rebuild the project
cmake --build $BuildDir --config $Configuration --target $Target
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build FAILED" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Build complete!"
