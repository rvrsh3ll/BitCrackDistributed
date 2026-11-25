param(
    [string]$BuildDir = "build_vs2022",
    [string]$Configuration = "Release",
    [string]$OutputDir = "dist/windows",
    [string]$BinaryName = "bitcrack-distributed.exe"
)

# Packages the console binary (the only binary: the Qt GUI was removed; run it
# with --dashboard for the web dashboard) with the DLLs it needs into
# <OutputDir>/cli.

$ErrorActionPreference = "Stop"

function Resolve-RepoRoot {
    $scriptRoot = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptRoot ".."))
}

function New-DirectoryIfMissing {
    param(
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Find-OpenSSLBin {
    <#
    .SYNOPSIS
    Finds OpenSSL bin directory from various possible locations.
    Checks environment variable, Chocolatey install, and common paths.
    #>
    # Check environment variable first
    if ($env:OPENSSL_DIR) {
        $candidate = Join-Path $env:OPENSSL_DIR "bin"
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    
    # Check OPENSSL_ROOT_DIR (CMake convention)
    if ($env:OPENSSL_ROOT_DIR) {
        $candidate = Join-Path $env:OPENSSL_ROOT_DIR "bin"
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    
    # Chocolatey default locations
    $candidates = @(
        "C:/Program Files/OpenSSL-Win64/bin",
        "C:/Program Files (x86)/OpenSSL-Win32/bin",
        "C:/Program Files/OpenSSL/bin",
        "D:/OpenSSL-Win64/bin",
        "C:/tools/openssl/bin"
    )
    
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    
    return $null
}

$repoRoot = Resolve-RepoRoot
# Resolve build path to a simple string (Resolve-Path returns PathInfo object)
$buildPath = (Resolve-Path (Join-Path $repoRoot $BuildDir)).Path
# Prefer the consolidated per-config build layout; fall back to legacy root build dir
$binaryInConfig = Join-Path $buildPath (Join-Path $Configuration $BinaryName)
$binaryInRoot = Join-Path $buildPath $BinaryName
if (Test-Path $binaryInConfig) {
    $binaryPath = $binaryInConfig
    Write-Host "Using binary from per-config dir: $binaryPath"
} elseif (Test-Path $binaryInRoot) {
    $binaryPath = $binaryInRoot
    Write-Host "Using binary from root build dir: $binaryPath"
} else {
    throw "Binary not found in expected locations: '$binaryInConfig' or '$binaryInRoot'. Build the project first or specify the correct configuration."
}

if (-not (Test-Path $binaryPath)) {
    throw "Binary '$binaryPath' not found. Build the project first."
}

$distRoot = Join-Path $repoRoot $OutputDir
$cliDir = Join-Path $distRoot "cli"
New-DirectoryIfMissing -Path $distRoot
New-DirectoryIfMissing -Path $cliDir

$cliTarget = Join-Path $cliDir "bitcrack-distributed-cli.exe"
Copy-Item -Path $binaryPath -Destination $cliTarget -Force

Write-Host ""
Write-Host "========== BitCrack Windows Packaging ==========" -ForegroundColor Cyan
Write-Host "CLI binary: $cliTarget" -ForegroundColor Gray
Write-Host ""

# Copy the CUDA probe helper if present
$cudaProbeCandidates = @(
    [System.IO.Path]::Combine($buildPath, $Configuration, 'bitcrack-cuda-probe.exe'),
    [System.IO.Path]::Combine($buildPath, 'bitcrack-cuda-probe.exe')
)
$cudaProbe = $null
foreach ($candidate in $cudaProbeCandidates) {
    if (Test-Path $candidate) { $cudaProbe = $candidate; break }
}
if ($cudaProbe) {
    Copy-Item -Path $cudaProbe -Destination (Join-Path $cliDir 'bitcrack-cuda-probe.exe') -Force
    Write-Host "[+] Copied CUDA probe helper" -ForegroundColor Green
}

# PDB next to the binary, if the build produced one
$pdb = [System.IO.Path]::ChangeExtension($binaryPath, '.pdb')
if (Test-Path $pdb) {
    Copy-Item -Path $pdb -Destination $cliDir -Force
}

$opensslBinDir = Find-OpenSSLBin
if ($opensslBinDir -and (Test-Path $opensslBinDir)) {
    $opensslDlls = @("libcrypto-3-x64.dll", "libssl-3-x64.dll", "libcrypto-3.dll", "libssl-3.dll")
    $copiedOpenSSL = 0
    foreach ($dll in $opensslDlls) {
        $src = Join-Path $opensslBinDir $dll
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $cliDir -Force
            $copiedOpenSSL++
        }
    }
    if ($copiedOpenSSL -gt 0) {
        Write-Host "[+] Copied $copiedOpenSSL OpenSSL DLL(s) from: $opensslBinDir" -ForegroundColor Green
    }
} else {
    Write-Host "[-] OpenSSL DLLs not found in standard locations" -ForegroundColor Yellow
    Write-Host "    If your app needs OpenSSL, manually copy:" -ForegroundColor Yellow
    Write-Host "    - libssl-3-x64.dll" -ForegroundColor Yellow
    Write-Host "    - libcrypto-3-x64.dll" -ForegroundColor Yellow
}

# Copy CUDA runtime DLLs (cudart) if available so CUDA-enabled builds run without relying on PATH
# and avoid loading a mismatched cudart from elsewhere on the system.
$cudaBins = @()
if ($env:CUDA_PATH) {
    $candidate = Join-Path $env:CUDA_PATH "bin"
    if (Test-Path $candidate) { $cudaBins += $candidate }
    $candidateX64 = Join-Path $candidate "x64"
    if (Test-Path $candidateX64) { $cudaBins += $candidateX64 }
}
if (-not $cudaBins -or $cudaBins.Count -eq 0) {
    $root = "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA"
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $bin = Join-Path $_.FullName "bin"
            if (Test-Path $bin) { $cudaBins += $bin }
            $binX64 = Join-Path $bin "x64"
            if (Test-Path $binX64) { $cudaBins += $binX64 }
        }
    }
}

$copiedCuda = $false
foreach ($binDir in $cudaBins) {
    Get-ChildItem -Path $binDir -Filter "cudart64_*.dll" -File -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $cliDir -Force
        $copiedCuda = $true
        Write-Host "[+] Copied CUDA runtime: $($_.Name)" -ForegroundColor Green
    }
    if ($copiedCuda) { break }
}
if (-not $copiedCuda) {
    Write-Host "[-] CUDA runtime DLL not found - CUDA builds will need CUDA 12.4+ installed on target" -ForegroundColor Yellow
}

# Ensure MSVC runtime (vcruntime/msvcp) dependencies are present in the dist folder
$system32 = "$env:SystemRoot\System32"
$msvcDlls = @("msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll")
$copiedMsvc = 0
foreach ($dll in $msvcDlls) {
    $src = Join-Path $system32 $dll
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $cliDir -Force
        $copiedMsvc++
    }
}
if ($copiedMsvc -gt 0) {
    Write-Host "[+] Copied $copiedMsvc MSVC runtime DLL(s)" -ForegroundColor Green
}


Write-Host ""
Write-Host "========== Packaging Complete ==========" -ForegroundColor Green
Write-Host "CLI distribution:  $cliDir" -ForegroundColor Green
Write-Host ""
Write-Host "DEPLOYMENT CHECKLIST:" -ForegroundColor Cyan
Write-Host "  [1] All DLLs in the folder ready for distribution" -ForegroundColor Gray
Write-Host "  [2] On target machine, the entire folder must be available" -ForegroundColor Gray
Write-Host "  [3] Run from the folder where all DLLs are located; add --dashboard and open http://127.0.0.1:3339/ for the web dashboard" -ForegroundColor Gray
if (-not $copiedOpenSSL -or $copiedOpenSSL -eq 0) {
    Write-Host "  [!] MISSING: OpenSSL DLLs - App may fail without them" -ForegroundColor Red
}
if (-not $copiedCuda -or $copiedCuda -eq 0) {
    Write-Host "  [!] CUDA build: cudart64_*.dll not found - install CUDA 12.4 on target" -ForegroundColor Yellow
}
Write-Host ""
