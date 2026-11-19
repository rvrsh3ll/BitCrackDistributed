param(
  [string]$BuildDir = 'build_vs2022',
  [string]$ElectronDir = 'gui/electron',
  [string]$OutputDir = 'dist/windows/electron'
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSCommandPath
Set-Location $root
$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = Resolve-Path (Join-Path $scriptRoot '..')
Set-Location $repoRoot

$buildPath = Join-Path $root $BuildDir
$electronPath = Join-Path $root $ElectronDir
$buildPath = Join-Path $repoRoot $BuildDir
$electronPath = Join-Path $repoRoot $ElectronDir

# Ensure electron has resources
$resourcesDir = Join-Path $electronPath 'resources'
if (-not (Test-Path $resourcesDir)) { New-Item -ItemType Directory -Path $resourcesDir | Out-Null }

# Copy the GUI binary so the electron builder can include it
 $distGuiPath = Join-Path $root 'dist/windows/gui/bitcrack-distributed-gui.exe'
 if (Test-Path $distGuiPath) {
   $exeSrc = $distGuiPath
 } else {
   $exeSrc = Join-Path $buildPath 'bitcrack-distributed.exe'
 }
$exeDst = Join-Path $resourcesDir 'bitcrack-distributed-gui.exe'
Copy-Item -Path $exeSrc -Destination $exeDst -Force
 $exeDst = Join-Path $resourcesDir 'bitcrack-distributed-gui.exe'
Copy-Item -Path $exeSrc -Destination $exeDst -Force

# Make sure we have node and npm available
$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) { Write-Warning 'npm not found. Install Node.js to continue.'; exit 1 }

# Build electron package
Push-Location $electronPath
Write-Host 'Installing electron packages...'
npm install
Write-Host 'Running electron builder...'
npm run package
Pop-Location

Write-Host "Electron build complete; artifacts (if any) will be under $OutputDir"
