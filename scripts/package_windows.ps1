param(
    [string]$BuildDir = "build_vs2022",
    [string]$Configuration = "Release",
    [string]$OutputDir = "dist/windows",
    [string]$BinaryName = "bitcrack-distributed.exe",
    [string]$QtDeployExe = ""
)

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

function Find-WinDeployQt {
    <#
    .SYNOPSIS
    Finds windeployqt.exe from various possible locations.
    Checks PATH, common Qt installations, and GitHub Actions paths.
    #>
    # Check PATH first
    $qtCmd = Get-Command windeployqt.exe -ErrorAction SilentlyContinue
    if ($qtCmd) {
        return $qtCmd.Source
    }
    
    # GitHub Actions installs Qt in specific locations (jurplel/install-qt-action)
    $githubActionsPaths = @(
        "C:/Qt/6.6.1/msvc2019_64/bin/windeployqt.exe",
        "C:/Qt/6.6.1/msvc2022_64/bin/windeployqt.exe",
        "D:/Qt/6.6.1/msvc2019_64/bin/windeployqt.exe"
    )
    
    # User Qt installations
    $userQtPaths = @(
        "C:/Qt/6.10.1/msvc2022_64/bin/windeployqt.exe",
        "C:/Qt/6.6.1/msvc2022_64/bin/windeployqt.exe",
        "C:/Qt/6.5.0/msvc2022_64/bin/windeployqt.exe",
        "C:/Qt/6.7.0/msvc2022_64/bin/windeployqt.exe"
    )
    
    $allCandidates = @()
    $allCandidates += $githubActionsPaths
    $allCandidates += $userQtPaths
    
    # Dynamic search in Qt root directories
    @("C:/Qt", "D:/Qt", "E:/Qt") | ForEach-Object {
        if (Test-Path $_) {
            Get-ChildItem -Path $_ -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $candidate = Join-Path $_.FullName "bin/windeployqt.exe"
                if (Test-Path $candidate) {
                    return $candidate
                }
            }
        }
    }
    
    foreach ($path in $allCandidates) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    return $null
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
$guiDir = Join-Path $distRoot "gui"
New-DirectoryIfMissing -Path $distRoot
New-DirectoryIfMissing -Path $cliDir
New-DirectoryIfMissing -Path $guiDir

$cliTarget = Join-Path $cliDir "bitcrack-distributed-cli.exe"
$guiTarget = Join-Path $guiDir "bitcrack-distributed-gui.exe"

Copy-Item -Path $binaryPath -Destination $cliTarget -Force
Copy-Item -Path $binaryPath -Destination $guiTarget -Force

Write-Host ""
Write-Host "========== BitCrack Windows Packaging ==========" -ForegroundColor Cyan
Write-Host "CLI binary: $cliTarget" -ForegroundColor Gray
Write-Host "GUI binary: $guiTarget" -ForegroundColor Gray
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
    Copy-Item -Path $cudaProbe -Destination (Join-Path $guiDir 'bitcrack-cuda-probe.exe') -Force
    Write-Host "[+] Copied CUDA probe helper" -ForegroundColor Green
}

$isElectron = $false
if ($args -contains '--electron') { $isElectron = $true }

# If BitCrackGUI.dll exists, it's a shared GUI library; run windeployqt to copy Qt DLLs for GUI target
$bitcrackGuiDllCandidates = @(
    [System.IO.Path]::Combine($buildPath, $Configuration, 'BitCrackGUI.dll'),
    [System.IO.Path]::Combine($buildPath, 'gui', $Configuration, 'BitCrackGUI.dll'),
    [System.IO.Path]::Combine($buildPath, 'gui', 'Release', 'BitCrackGUI.dll')
)
$bitcrackGuiDll = $null
foreach ($candidate in $bitcrackGuiDllCandidates) {
    if (Test-Path $candidate) { $bitcrackGuiDll = $candidate; break }
}
if ($bitcrackGuiDll) { 
    Write-Host "[+] Found GUI DLL: $bitcrackGuiDll" -ForegroundColor Green
} else { 
    Write-Host "[-] No GUI DLL found" -ForegroundColor Yellow
}
    if ($bitcrackGuiDll -and (Test-Path $bitcrackGuiDll)) {
    Copy-Item -Path $bitcrackGuiDll -Destination $guiDir -Force
    Copy-Item -Path $bitcrackGuiDll -Destination $cliDir -Force
    $pdb = [System.IO.Path]::ChangeExtension($bitcrackGuiDll, ".pdb")
    if (Test-Path $pdb) {
        Copy-Item -Path $pdb -Destination $guiDir -Force
        Copy-Item -Path $pdb -Destination $cliDir -Force
    }
    Write-Host "[+] Copied BitCrackGUI.dll to dist directories" -ForegroundColor Green
    
    if (-not $QtDeployExe) {
        $QtDeployExe = Find-WinDeployQt
    }
    
    if ($QtDeployExe -and (Test-Path $QtDeployExe)) {
        Write-Host "[+] Found windeployqt: $QtDeployExe" -ForegroundColor Green
        
        $opensslBinPath = Find-OpenSSLBin
        $openSSLRootDir = if ($opensslBinPath) { Split-Path $opensslBinPath } else { $null }
        
        if ($openSSLRootDir) {
            Write-Host "[+] Running windeployqt with OpenSSL support: $openSSLRootDir" -ForegroundColor Cyan
            & $QtDeployExe --release --dir $guiDir --openssl-root "$openSSLRootDir" $bitcrackGuiDll
        } else {
            Write-Host "[*] Running windeployqt (OpenSSL not found, qopensslbackend may be unavailable)" -ForegroundColor Cyan
            & $QtDeployExe --release --dir $guiDir $bitcrackGuiDll
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] windeployqt succeeded - Qt dependencies copied" -ForegroundColor Green
        } else {
            Write-Warning "[!] windeployqt exited with code $LASTEXITCODE. Some Qt DLLs may be missing."
        }
    } else {
        Write-Host "[-] windeployqt.exe not found - attempting manual Qt DLL discovery" -ForegroundColor Yellow
    }
}

# Copy our own shared GUI DLL into the dist directory so the exe can load it
if ($bitcrackGuiDll -and (Test-Path $bitcrackGuiDll)) {
    Copy-Item -Path $bitcrackGuiDll -Destination $guiDir -Force
    # Copy GUI DLL into CLI folder as well if main binary links against it
    Copy-Item -Path $bitcrackGuiDll -Destination $cliDir -Force
    $pdb = [System.IO.Path]::ChangeExtension($bitcrackGuiDll, ".pdb")
    if (Test-Path $pdb) {
        Copy-Item -Path $pdb -Destination $guiDir -Force
        Copy-Item -Path $pdb -Destination $cliDir -Force
    }
}

Write-Host "CLI binary: $cliTarget"
Write-Host "GUI binary (with Qt deps if available): $guiTarget"
# Copy OpenSSL runtime DLLs if available to both CLI and GUI output directories
$opensslBinDir = Find-OpenSSLBin
if ($opensslBinDir -and (Test-Path $opensslBinDir)) {
    $opensslDlls = @("libcrypto-3-x64.dll", "libssl-3-x64.dll", "libcrypto-3.dll", "libssl-3.dll")
    $copiedOpenSSL = 0
    foreach ($dll in $opensslDlls) {
        $src = Join-Path $opensslBinDir $dll
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $cliDir -Force
            Copy-Item -Path $src -Destination $guiDir -Force
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
        Copy-Item -Path $_.FullName -Destination $guiDir -Force
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
        Copy-Item -Path $src -Destination $guiDir -Force
        $copiedMsvc++
    }
}
if ($copiedMsvc -gt 0) {
    Write-Host "[+] Copied $copiedMsvc MSVC runtime DLL(s)" -ForegroundColor Green
}

# Copy Qt DLLs and plugin directories from GUI dir to CLI dir so the CLI binary can run too
$qtDllCount = 0
Get-ChildItem -Path $guiDir -Filter "Qt6*.dll" -File -ErrorAction SilentlyContinue | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $cliDir -Force
    $qtDllCount++
}
if ($qtDllCount -gt 0) {
    Write-Host "[+] Copied $qtDllCount Qt6 DLL(s) to CLI directory" -ForegroundColor Green
}

$pluginsDirs = @()
foreach ($plugin in @('platforms','styles','imageformats','iconengines','generic','tls','networkinformation')) {
    $srcPlugin = Join-Path $guiDir $plugin
    if (Test-Path $srcPlugin) { 
        Copy-Item -Path $srcPlugin -Destination $cliDir -Recurse -Force
        $pluginsDirs += $plugin
    }
}
if ($pluginsDirs.Count -gt 0) {
    Write-Host "[+] Copied $($pluginsDirs.Count) Qt plugin directory(ies)" -ForegroundColor Green
}

Write-Host ""
Write-Host "========== Packaging Complete ==========" -ForegroundColor Green
Write-Host "CLI distribution:  $cliDir" -ForegroundColor Green
Write-Host "GUI distribution:  $guiDir" -ForegroundColor Green
Write-Host ""
Write-Host "DEPLOYMENT CHECKLIST:" -ForegroundColor Cyan
Write-Host "  [1] All DLLs in both folders ready for distribution" -ForegroundColor Gray
Write-Host "  [2] On target machine, entire folder must be available" -ForegroundColor Gray
Write-Host "  [3] Run from the folder where all DLLs are located" -ForegroundColor Gray
if (-not $copiedOpenSSL -or $copiedOpenSSL -eq 0) {
    Write-Host "  [!] MISSING: OpenSSL DLLs - App may fail without them" -ForegroundColor Red
}
if (-not $copiedCuda -or $copiedCuda -eq 0) {
    Write-Host "  [!] CUDA build: cudart64_*.dll not found - install CUDA 12.4 on target" -ForegroundColor Yellow
}
Write-Host ""

if ($isElectron) {
    Write-Host 'Building electron package...'
    $buildElectron = Join-Path $repoRoot 'scripts/build_electron.ps1'
    if (Test-Path $buildElectron) {
        powershell -ExecutionPolicy Bypass -File $buildElectron -BuildDir $BuildDir
    } else {
        Write-Warning 'Electron build script missing: scripts/build_electron.ps1'
    }
}
