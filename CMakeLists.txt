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

# Enable CUDA if available
include(CheckLanguage)
if(NOT DISABLE_CUDA)
    check_language(CUDA)
    if(CMAKE_CUDA_COMPILER)
        enable_language(CUDA)
        set(CUDA_AVAILABLE ON)
        message(STATUS "CUDA found - GPU acceleration enabled")
    else()
        # Try find_package as fallback
        find_package(CUDAToolkit QUIET)
        if(CUDAToolkit_FOUND)
            set(CUDA_AVAILABLE ON)
            message(STATUS "CUDA found via find_package - GPU acceleration enabled")
        else()
            set(CUDA_AVAILABLE OFF)
            message(STATUS "CUDA not found - CPU only mode")
        endif()
    endif()
else()
    set(CUDA_AVAILABLE OFF)
    message(STATUS "CUDA explicitly disabled via DISABLE_CUDA option")
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

# Find GUI framework (Qt or equivalent)
option(BITCRACK_ENABLE_GUI "Build the Qt-based Electrum GUI" ON)
option(BITCRACK_COPY_BUILD_TO_DIST "Copy built binaries to dist directory during build" ON)

set(_bitcrack_qt_components Core Widgets Network)

if(BITCRACK_ENABLE_GUI)
    # Prefer Qt6 but fall back to Qt5 if needed. Users who want GUI builds should install Qt
    # (MSVC x64) locally or bundle redistributables via windeployqt.
    find_package(Qt6 QUIET COMPONENTS ${_bitcrack_qt_components})
else()
    set(Qt6_FOUND OFF)
endif()
if(Qt6_FOUND)
    set(GUI_AVAILABLE ON)
    set(BITCRACK_QT_VERSION 6)
    message(STATUS "Qt6 found - GUI enabled")
elseif(BITCRACK_ENABLE_GUI)
    find_package(Qt5 QUIET COMPONENTS ${_bitcrack_qt_components})
    if(Qt5_FOUND)
        set(GUI_AVAILABLE ON)
        set(BITCRACK_QT_VERSION 5)
        message(STATUS "Qt5 found - GUI enabled")
    else()
        set(GUI_AVAILABLE OFF)
        message(WARNING "BITCRACK_ENABLE_GUI is ON but Qt was not found - building console mode only")
    endif()
else()
    set(GUI_AVAILABLE OFF)
    message(STATUS "GUI disabled via BITCRACK_ENABLE_GUI=OFF")
endif()

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

if(GUI_AVAILABLE)
    add_subdirectory(gui)
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

# On Windows with GUI, use WIN32 subsystem to hide console window
if(WIN32 AND GUI_AVAILABLE)
    set_target_properties(bitcrack-distributed PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

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

if(GUI_AVAILABLE)
    target_link_libraries(bitcrack-distributed PRIVATE BitCrackGUI)
    # Compile the main binary with GUI_AVAILABLE so GUI code paths are enabled
    target_compile_definitions(bitcrack-distributed PRIVATE GUI_AVAILABLE)
    # Allow the main binary to include and link Qt symbols
    set(_qt_prefix Qt${BITCRACK_QT_VERSION})
    target_link_libraries(bitcrack-distributed PRIVATE ${_qt_prefix}::Core ${_qt_prefix}::Widgets ${_qt_prefix}::Network)
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

## Copy build outputs to dist tree for easy GUI testing/packaging
if(BITCRACK_COPY_BUILD_TO_DIST AND WIN32)
    set(DIST_ROOT "${CMAKE_SOURCE_DIR}/dist/windows")
    set(DIST_GUI_DIR "${DIST_ROOT}/gui")
    set(DIST_CLI_DIR "${DIST_ROOT}/cli")

    add_custom_command(TARGET bitcrack-distributed POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DIST_GUI_DIR}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DIST_CLI_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:bitcrack-distributed> "${DIST_CLI_DIR}/bitcrack-distributed-cli.exe"
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:bitcrack-distributed> "${DIST_GUI_DIR}/bitcrack-distributed-gui.exe"
        COMMENT "Copy bitcrack-distributed binary to ${DIST_ROOT}"
    )

    # Attempt to copy PDBs if present
    # add_custom_command(TARGET bitcrack-distributed POST_BUILD
    #     COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_PDB_FILE:bitcrack-distributed> "${DIST_CLI_DIR}/bitcrack-distributed-cli.pdb"
    #     COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_PDB_FILE:bitcrack-distributed> "${DIST_GUI_DIR}/bitcrack-distributed-gui.pdb"
    # )

    # BitCrackGUI post-build copy is handled in gui/CMakeLists.txt
endif()