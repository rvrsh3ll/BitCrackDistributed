cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
project(BitCrackDistributed VERSION 1.0.0 LANGUAGES CXX)

# Preserve compatibility with helper downloads invoked via FetchContent_Populate.
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()

# Build options
option(DISABLE_CUDA "Disable building CUDA components" OFF)
option(BITCRACK_DISABLE_GPU "Disable building all GPU components (CUDA and OpenCL)" OFF)
option(BITCRACK_BUILD_TESTS "Build unit tests (Catch2)" ON)
option(BITCRACK_NATIVE "Optimize for the build host CPU (-march=native; binaries are NOT portable to other machines)" OFF)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-specific settings
if(WIN32)
    # Define Windows version for Winsock2 and other Windows APIs (Windows 7+)
    add_compile_definitions(_WIN32_WINNT=0x0601)
    # Link Winsock2
    list(APPEND CMAKE_SYSTEM_LIBRARIES ws2_32)
endif()

# Consolidate runtime, archive and library output directories per-config
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG>)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG>)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG>)

# CUDA architectures; see the "CUDA target architectures" block below. Declared
# here because it must feed CMAKE_CUDA_ARCHITECTURES before enable_language(CUDA).
set(BITCRACK_CUDA_ARCH "75;86;89;120" CACHE STRING
    "CUDA architectures to build (CMake CUDA_ARCHITECTURES syntax, or 'native')")

# Enable CUDA if available
#
# check_language(CUDA) only finds nvcc when it is on PATH (or CUDACXX /
# CMAKE_CUDA_COMPILER is set). Distro installs such as Fedora/Nobara put the
# toolkit in /usr/local/cuda without adding its bin/ to PATH, so we also look
# for nvcc next to a CUDAToolkit found by find_package and in the usual install
# prefixes. CUDA_AVAILABLE is only ever turned ON together with
# enable_language(CUDA): without the CUDA language the .cu kernels would be
# silently dropped from GPUKernels and the final link would fail with
# undefined bcd_cuda_* references.
include(CheckLanguage)
if(NOT DISABLE_CUDA)
    check_language(CUDA)
    if(NOT CMAKE_CUDA_COMPILER)
        find_package(CUDAToolkit QUIET)
        set(_bitcrack_nvcc_candidates)
        if(CUDAToolkit_NVCC_EXECUTABLE)
            list(APPEND _bitcrack_nvcc_candidates "${CUDAToolkit_NVCC_EXECUTABLE}")
        endif()
        if(CUDAToolkit_BIN_DIR)
            list(APPEND _bitcrack_nvcc_candidates "${CUDAToolkit_BIN_DIR}/nvcc")
        endif()
        foreach(_env CUDA_PATH CUDA_HOME CUDA_ROOT CUDAToolkit_ROOT)
            if(DEFINED ENV{${_env}})
                list(APPEND _bitcrack_nvcc_candidates "$ENV{${_env}}/bin/nvcc")
            endif()
        endforeach()
        list(APPEND _bitcrack_nvcc_candidates /usr/local/cuda/bin/nvcc /opt/cuda/bin/nvcc)
        file(GLOB _bitcrack_versioned_nvcc /usr/local/cuda-*/bin/nvcc)
        if(_bitcrack_versioned_nvcc)
            list(SORT _bitcrack_versioned_nvcc COMPARE NATURAL ORDER DESCENDING)
            list(APPEND _bitcrack_nvcc_candidates ${_bitcrack_versioned_nvcc})
        endif()
        list(APPEND _bitcrack_nvcc_candidates /usr/bin/nvcc)
        set(_bitcrack_nvcc "")
        foreach(_cand IN LISTS _bitcrack_nvcc_candidates)
            if(EXISTS "${_cand}" AND NOT IS_DIRECTORY "${_cand}")
                set(_bitcrack_nvcc "${_cand}")
                break()
            endif()
        endforeach()
        if(_bitcrack_nvcc)
            message(STATUS "nvcc not on PATH; using ${_bitcrack_nvcc}")
            set(CMAKE_CUDA_COMPILER "${_bitcrack_nvcc}" CACHE FILEPATH "CUDA compiler" FORCE)
        elseif(CUDAToolkit_FOUND)
            message(FATAL_ERROR
                "CUDA toolkit found (${CUDAToolkit_LIBRARY_DIR}) but nvcc not found. "
                "Add the toolkit's bin directory to PATH (e.g. export PATH=/usr/local/cuda/bin:$PATH), "
                "or pass -DCMAKE_CUDA_COMPILER=/path/to/nvcc, or configure a CPU-only build with "
                "-DDISABLE_CUDA=ON.")
        endif()
    endif()
    if(CMAKE_CUDA_COMPILER)
        # Every target that device-links GPUKernels (bitcrack-distributed,
        # bitcrack_tests) must use the same architectures as the
        # kernels themselves. Left to CMake's default (sm_75) the consumer's
        # device link drops the sm_120-only kernel objects: bitcrack_tests then
        # fails to link (undefined __cudaRegisterLinkedBinary_*) and the
        # executables carry no kernel image for the GPU.
        set(CMAKE_CUDA_ARCHITECTURES "${BITCRACK_CUDA_ARCH}")
        enable_language(CUDA)
        set(CUDA_AVAILABLE ON)
        message(STATUS "CUDA found (${CMAKE_CUDA_COMPILER}) - GPU acceleration enabled")
    else()
        set(CUDA_AVAILABLE OFF)
        message(STATUS "CUDA not found - CPU only mode")
    endif()
else()
    set(CUDA_AVAILABLE OFF)
    message(STATUS "CUDA explicitly disabled via DISABLE_CUDA option")
endif()

# ---------------------------------------------------------------------------
# CUDA target architectures (real search kernels, WP1+).
#
# Default to a portable PTX+SASS spread that includes the user's RTX 5070
# (Blackwell, compute capability 12.0 / sm_120). Pass -DBITCRACK_CUDA_ARCH=native
# to build only for the build host's GPU, or an explicit list such as "89;120".
# Building any sm_120 target needs CUDA 12.8+ (older nvcc has no Blackwell
# support); we fail configure with a clear message rather than a cryptic nvcc
# error. DISABLE_CUDA / CPU-only builds never reach this block.
# ---------------------------------------------------------------------------
# (BITCRACK_CUDA_ARCH itself is declared above, before enable_language(CUDA).)

if(CUDA_AVAILABLE)
    find_package(CUDAToolkit REQUIRED)
    set(_bitcrack_needs_128 OFF)
    foreach(_a IN LISTS BITCRACK_CUDA_ARCH)
        string(REGEX MATCH "^([0-9]+)" _anum "${_a}")
        if(_anum AND _anum GREATER_EQUAL 120)
            set(_bitcrack_needs_128 ON)
        endif()
    endforeach()
    if(_bitcrack_needs_128 AND CUDAToolkit_VERSION VERSION_LESS "12.8")
        message(FATAL_ERROR
            "BITCRACK_CUDA_ARCH requests sm_120 (Blackwell, e.g. RTX 5070) but the "
            "detected CUDA toolkit is ${CUDAToolkit_VERSION}. Install CUDA 12.8 or "
            "newer, or set -DBITCRACK_CUDA_ARCH to a list without 120 (e.g. \"75;86;89\").")
    endif()
    message(STATUS "CUDA toolkit ${CUDAToolkit_VERSION}; building for architectures: ${BITCRACK_CUDA_ARCH}")
endif()

# Find required packages
find_package(Threads REQUIRED)

# Set OpenSSL root for Windows if vcpkg is not in use
if(WIN32 AND NOT CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg")
    # Check environment variable first
    if(DEFINED ENV{OPENSSL_ROOT_DIR})
        set(_env_openssl "$ENV{OPENSSL_ROOT_DIR}")
        # Normalize path separators
        string(REPLACE "\\" "/" _env_openssl "${_env_openssl}")
        if(EXISTS "${_env_openssl}")
            set(OPENSSL_ROOT_DIR "${_env_openssl}" CACHE PATH "OpenSSL root directory")
            message(STATUS "Using OpenSSL from environment: ${OPENSSL_ROOT_DIR}")
        endif()
    endif()
    
    # If not set by environment, check common installation paths
    if(NOT OPENSSL_ROOT_DIR)
        set(_openssl_paths
            "C:/Program Files/OpenSSL-Win64"
            "C:/Program Files/OpenSSL"
            "C:/Program Files (x86)/OpenSSL"
            "C:/Program Files (x86)/OpenSSL-Win64"
        )
        
        foreach(_path IN LISTS _openssl_paths)
            if(EXISTS "${_path}")
                set(OPENSSL_ROOT_DIR "${_path}" CACHE PATH "OpenSSL root directory")
                message(STATUS "Found OpenSSL at: ${OPENSSL_ROOT_DIR}")
                break()
            endif()
        endforeach()
    endif()
    
    if(OPENSSL_ROOT_DIR)
        list(APPEND CMAKE_PREFIX_PATH "${OPENSSL_ROOT_DIR}")
        message(STATUS "CMAKE_PREFIX_PATH includes: ${OPENSSL_ROOT_DIR}")
    else()
        message(WARNING "OpenSSL not found in common locations. Set OPENSSL_ROOT_DIR manually.")
    endif()
endif()

# Find OpenSSL (use imported targets for portability)
find_package(OpenSSL REQUIRED)

# Find optional packages
find_package(OpenCL QUIET)
if(OpenCL_FOUND)
    set(OPENCL_AVAILABLE ON)
    message(STATUS "OpenCL found - OpenCL GPU acceleration enabled")
else()
    set(OPENCL_AVAILABLE OFF)
    message(STATUS "OpenCL not found")
endif()

# The Qt GUI was removed; the node serves an HTML dashboard instead
# (--dashboard, see README "Web dashboard"). Nothing here needs Qt.
if(DEFINED BITCRACK_ENABLE_GUI AND BITCRACK_ENABLE_GUI)
    message(WARNING "BITCRACK_ENABLE_GUI is ignored: the Qt GUI was removed. Run the node with --dashboard "
                    "and open http://127.0.0.1:3339/ in a browser instead.")
endif()
option(BITCRACK_COPY_BUILD_TO_DIST "Copy built binaries to dist directory during build" ON)

# Add nlohmann/json for configuration
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
    DOWNLOAD_NO_EXTRACT TRUE
)
FetchContent_GetProperties(nlohmann_json)
if(NOT nlohmann_json_POPULATED)
    FetchContent_Populate(nlohmann_json)
endif()
add_library(nlohmann_json INTERFACE)
add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
target_include_directories(nlohmann_json INTERFACE ${nlohmann_json_SOURCE_DIR})

# Include directories
include_directories(include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Add subdirectories
add_subdirectory(src)

if(BITCRACK_DISABLE_GPU)
    # The executable always links the GPU support library; with all GPU
    # components disabled it is built as a CPU-only stub (GPUManager compiled
    # without the CUDA/OpenCL defines) so the link keeps working.
    # (docs/launch-blockers used to warn that this option broke the build.)
    set(CUDA_AVAILABLE OFF)
    set(OPENCL_AVAILABLE OFF)
    message(STATUS "GPU components disabled via BITCRACK_DISABLE_GPU option (stub support library only)")
endif()
add_subdirectory(gpu)

add_subdirectory(network)

if(BITCRACK_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# Compiler-specific options
if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    # Suppress OpenSSL deprecation warnings for MSVC
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DOPENSSL_API_COMPAT=0x10100000L)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3")
    # Suppress OpenSSL deprecation warnings for GCC/Clang
    add_compile_options(-Wno-deprecated-declarations)
    # Allow infinity/NaN for JSON library on macOS/Linux
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
        add_compile_options(-fno-fast-math)
    endif()
endif()

# Platform-specific configurations
if(WIN32)
    add_definitions(-DWINDOWS)
elseif(APPLE)
    add_definitions(-DMACOS)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    find_library(IOKIT_LIBRARY IOKit)
else()
    add_definitions(-DLINUX)
endif()

# Create main executable
add_executable(bitcrack-distributed
    src/main.cpp
)

# A tiny CUDA probe helper. This runs CUDA Driver API initialization in a separate process
# so that a catastrophic driver failure cannot kill the main application.
if(WIN32 AND CUDA_AVAILABLE)
    find_package(CUDAToolkit REQUIRED)
    add_executable(bitcrack-cuda-probe
        gpu/cuda_probe_main.cpp
    )
    target_include_directories(bitcrack-cuda-probe PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(bitcrack-cuda-probe PRIVATE
        CUDA::cudart
    )
    target_compile_definitions(bitcrack-cuda-probe PRIVATE CUDA_AVAILABLE)
endif()

# Set output directory
set_target_properties(bitcrack-distributed PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
)

target_include_directories(bitcrack-distributed PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
)

# Link libraries
target_link_libraries(bitcrack-distributed PRIVATE
    BitCrackCore
    NetworkLayer
    GPUKernels
    ${CMAKE_THREAD_LIBS_INIT}
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(OPENCL_AVAILABLE)
    target_link_libraries(bitcrack-distributed PRIVATE ${OpenCL_LIBRARIES})
endif()

if(WIN32)
    target_link_libraries(bitcrack-distributed PRIVATE ws2_32 iphlpapi)
elseif(APPLE)
    target_link_libraries(bitcrack-distributed PRIVATE ${COREFOUNDATION_LIBRARY} ${IOKIT_LIBRARY})
endif()

# Configure file with build options
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
)

## (Move PDB property auto-apply block to end of file so it runs after all targets are defined)
# On MSVC, ensure compile PDB names/locations are explicit for all local targets
# so the generated MSBuild projects don't accidentally set a directory as the
# ProgramDataBaseFileName which leads to an MSB3025 error when MSBuild attempts
# to copy PDB files from the intermediate dir.
if(MSVC)
    get_property(_allTargets GLOBAL PROPERTY TARGETS)
    foreach(_t IN LISTS _allTargets)
        if(TARGET ${_t})
            get_target_property(_imported ${_t} IMPORTED)
            if(NOT _imported)
                get_target_property(_type ${_t} TYPE)
                if(NOT _type STREQUAL "INTERFACE_LIBRARY")
                    set_target_properties(${_t} PROPERTIES
                        COMPILE_PDB_NAME ${_t}
                        COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${_t}/$<CONFIG>"
                    )
                endif()
            endif()
        endif()
    endforeach()
endif()

## Copy build outputs to the dist tree for packaging
if(BITCRACK_COPY_BUILD_TO_DIST AND WIN32)
    set(DIST_ROOT "${CMAKE_SOURCE_DIR}/dist/windows")
    set(DIST_CLI_DIR "${DIST_ROOT}/cli")

    add_custom_command(TARGET bitcrack-distributed POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DIST_CLI_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:bitcrack-distributed> "${DIST_CLI_DIR}/bitcrack-distributed-cli.exe"
        COMMENT "Copy bitcrack-distributed binary to ${DIST_ROOT}"
    )

    # Attempt to copy PDBs if present
    # add_custom_command(TARGET bitcrack-distributed POST_BUILD
    #     COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_PDB_FILE:bitcrack-distributed> "${DIST_CLI_DIR}/bitcrack-distributed-cli.pdb"
    # )
endif()