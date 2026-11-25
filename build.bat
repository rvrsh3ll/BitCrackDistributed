@echo off
setlocal enabledelayedexpansion
REM ===========================================================================
REM BitCrack Distributed - Windows build helper (Visual Studio 2022, x64)
REM
REM Usage: build.bat [Release^|Debug^|RelWithDebInfo] [no_copy^|copy] [tests] [clean] [nocuda]
REM   Release/Debug/RelWithDebInfo  configuration to build (default: Release)
REM   no_copy / copy    disable/enable copying outputs to dist\windows (default: copy)
REM   tests             also build bitcrack_tests (fetches Catch2; slower)
REM   clean             delete build_vs2022 before configuring
REM   nocuda            force a CPU-only build even when CUDA is installed
REM
REM Auto-detects CUDA via CUDA_PATH / nvcc on PATH. Can be run from any
REM directory (including Explorer): execution is forced to the repo root.
REM ===========================================================================

REM Force execution from the repository root (the directory holding this file)
pushd "%~dp0"

set CONFIG=Release
set COPY_DIST=ON
set BUILD_TESTS=OFF
set FORCE_FETCH_CATCH2=OFF
set CUDA_OPT=
set CLEAN=0

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="Release" set CONFIG=Release
if /i "%~1"=="Debug" set CONFIG=Debug
if /i "%~1"=="RelWithDebInfo" set CONFIG=RelWithDebInfo
if /i "%~1"=="no_copy" set COPY_DIST=OFF
if /i "%~1"=="copy" set COPY_DIST=ON
if /i "%~1"=="tests" ( set BUILD_TESTS=ON & set FORCE_FETCH_CATCH2=ON )
if /i "%~1"=="clean" set CLEAN=1
if /i "%~1"=="nocuda" set CUDA_OPT=-DDISABLE_CUDA=ON
shift
goto parse_args
:args_done

REM Auto-detect CUDA (nvcc on PATH or CUDA_PATH set) unless disabled explicitly
if "%CUDA_OPT%"=="" (
    set HAVE_CUDA=0
    if defined CUDA_PATH if exist "%CUDA_PATH%\bin\nvcc.exe" set HAVE_CUDA=1
    if !HAVE_CUDA!==0 where nvcc >nul 2>nul && set HAVE_CUDA=1
    if !HAVE_CUDA!==0 (
        echo CUDA not found - configuring a CPU-only build
        set CUDA_OPT=-DDISABLE_CUDA=ON
    ) else (
        echo CUDA detected - GPU build enabled
    )
)

where cmake >nul 2>nul
if errorlevel 1 (
    echo Error: cmake not found on PATH. Install CMake 3.18+ ^(Visual Studio installer or cmake.org^).
    popd
    exit /b 1
)

if "%CLEAN%"=="1" (
    echo Cleaning build_vs2022...
    if exist build_vs2022 rmdir /s /q build_vs2022
)

echo Configuring ^(VS2022 x64, %CONFIG%, copy_to_dist=%COPY_DIST%, tests=%BUILD_TESTS%^)...
cmake -S . -B build_vs2022 -G "Visual Studio 17 2022" -A x64 ^
    -DBITCRACK_COPY_BUILD_TO_DIST=%COPY_DIST% ^
    -DBITCRACK_BUILD_TESTS=%BUILD_TESTS% ^
    -DBITCRACK_FORCE_FETCH_CATCH2=%FORCE_FETCH_CATCH2% ^
    %CUDA_OPT%
if errorlevel 1 (
    echo Configure failed.
    popd
    exit /b 1
)

echo Building %CONFIG%...
cmake --build build_vs2022 --config %CONFIG% -- /m:4
if errorlevel 1 (
    echo Build failed.
    popd
    exit /b 1
)

if "%BUILD_TESTS%"=="ON" (
    echo Building tests...
    cmake --build build_vs2022 --config %CONFIG% --target bitcrack_tests -- /m:4
    if errorlevel 1 (
        echo Test build failed.
        popd
        exit /b 1
    )
    echo Run tests: build_vs2022\tests\%CONFIG%\bitcrack_tests.exe
)

echo.
echo Build complete: build_vs2022\%CONFIG%\bitcrack-distributed.exe
if /i "%COPY_DIST%"=="ON" echo Packaged copy: dist\windows\cli
popd
endlocal
exit /b 0
