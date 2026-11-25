# Core BitCrack engine library
set(_BITCRACK_CORE_SOURCE_CANDIDATES
    BitCrackEngine.cpp
    ConfigManager.cpp
    ResourceMonitor.cpp
    Logger.cpp
    EllipticCurve.cpp
    AddressGenerator.cpp
    KeyUtils.cpp
    PuzzleManager.cpp
    BitcoinWallet.cpp
    ElectrumClient.cpp
    PuzzleBalance.cpp
    Secp256k1Scan.cpp
    WorkState.cpp
    KeyspaceBlock.cpp
    KeyspaceChainStore.cpp
    ShutdownSignal.cpp
    RewardAddress.cpp
    HexMath.cpp
    ClaimCheck.cpp
    NodeIdentity.cpp
    SecretFile.cpp
    PlatformPaths.cpp
    TlsCa.cpp
)

# Keep headers optional; project may be partial
set(_BITCRACK_CORE_HEADER_CANDIDATES
    ${CMAKE_SOURCE_DIR}/include/BitCrackEngine.h
    ${CMAKE_SOURCE_DIR}/include/Config.h
    ${CMAKE_SOURCE_DIR}/include/ConfigManager.h
    ${CMAKE_SOURCE_DIR}/include/ResourceMonitor.h
    ${CMAKE_SOURCE_DIR}/include/Logger.h
    ${CMAKE_SOURCE_DIR}/include/EllipticCurve.h
    ${CMAKE_SOURCE_DIR}/include/AddressGenerator.h
    ${CMAKE_SOURCE_DIR}/include/KeyUtils.h
    ${CMAKE_SOURCE_DIR}/include/PuzzleManager.h
    ${CMAKE_SOURCE_DIR}/include/BitcoinWallet.h
    ${CMAKE_SOURCE_DIR}/include/PuzzleBalance.h
    ${CMAKE_SOURCE_DIR}/include/Secp256k1Scan.h
    ${CMAKE_SOURCE_DIR}/include/WorkState.h
    ${CMAKE_SOURCE_DIR}/include/KeyspaceBlock.h
    ${CMAKE_SOURCE_DIR}/include/KeyspaceChainStore.h
    ${CMAKE_SOURCE_DIR}/include/ShutdownSignal.h
    ${CMAKE_SOURCE_DIR}/include/RewardAddress.h
    ${CMAKE_SOURCE_DIR}/include/HexMath.h
    ${CMAKE_SOURCE_DIR}/include/ClaimCheck.h
    ${CMAKE_SOURCE_DIR}/include/NodeIdentity.h
    ${CMAKE_SOURCE_DIR}/include/SecretFile.h
    ${CMAKE_SOURCE_DIR}/include/PlatformPaths.h
    ${CMAKE_SOURCE_DIR}/include/TlsCa.h
)

set(BITCRACK_CORE_HEADERS)
foreach(HDR ${_BITCRACK_CORE_HEADER_CANDIDATES})
    if(EXISTS ${HDR})
        list(APPEND BITCRACK_CORE_HEADERS ${HDR})
    endif()
endforeach()

# Filter existing sources
set(BITCRACK_CORE_SOURCES)
foreach(SRC ${_BITCRACK_CORE_SOURCE_CANDIDATES})
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${SRC})
        list(APPEND BITCRACK_CORE_SOURCES ${SRC})
    else()
        message(WARNING "Core source missing: ${CMAKE_CURRENT_SOURCE_DIR}/${SRC}")
    endif()
endforeach()

# If no sources, create a dummy to satisfy the linker
if(NOT BITCRACK_CORE_SOURCES)
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dummy_core.cpp "#include <stddef.h>\nint __bitcrack_core_dummy = 0;\n")
    list(APPEND BITCRACK_CORE_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/dummy_core.cpp)
endif()

# Create the core library
add_library(BitCrackCore STATIC 
    ${BITCRACK_CORE_SOURCES}
    ${BITCRACK_CORE_HEADERS}
)

# Include directories
target_include_directories(BitCrackCore PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Optional: Find and include Asio (standalone or Boost) for Electrum client
find_package(Boost QUIET COMPONENTS system)
if(Boost_FOUND)
    target_include_directories(BitCrackCore PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(BitCrackCore ${Boost_LIBRARIES})
    target_compile_definitions(BitCrackCore PRIVATE BOOST_ASIO_AVAILABLE)
    message(STATUS "Boost.Asio found - using Boost in BitCrackCore")
else()
    find_path(ASIO_INCLUDE_DIR asio.hpp)
    if(NOT ASIO_INCLUDE_DIR)
        include(FetchContent)
        FetchContent_Declare(
            asio
            URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-30-2.tar.gz
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_GetProperties(asio)
        if(NOT asio_POPULATED)
            FetchContent_Populate(asio)
        endif()
        if(EXISTS ${asio_SOURCE_DIR}/asio.hpp)
            set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR})
        elseif(EXISTS ${asio_SOURCE_DIR}/asio/include/asio.hpp)
            set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include)
        elseif(EXISTS ${asio_SOURCE_DIR}/include/asio.hpp)
            set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/include)
        endif()
    endif()
    if(ASIO_INCLUDE_DIR AND EXISTS ${ASIO_INCLUDE_DIR}/asio.hpp)
        target_include_directories(BitCrackCore PRIVATE ${ASIO_INCLUDE_DIR})
        target_compile_definitions(BitCrackCore PRIVATE ASIO_STANDALONE ASIO_AVAILABLE)
        message(STATUS "Standalone ASIO available - using in BitCrackCore")
    endif()
endif()

# Link libraries
target_link_libraries(BitCrackCore 
    ${CMAKE_THREAD_LIBS_INIT}
    ${OPENSSL_SSL_LIBRARY}
    ${OPENSSL_CRYPTO_LIBRARY}
)

if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(BitCrackCore nlohmann_json::nlohmann_json)
endif()

# Platform-specific libraries
if(WIN32)
    target_link_libraries(BitCrackCore pdh winhttp)
elseif(APPLE)
    target_link_libraries(BitCrackCore ${COREFOUNDATION_LIBRARY} ${IOKIT_LIBRARY})
elseif(UNIX)
    # Linux libraries for system monitoring
    find_library(PROCPS_LIBRARY procps)
    if(PROCPS_LIBRARY)
        target_link_libraries(BitCrackCore ${PROCPS_LIBRARY})
    endif()
endif()

# Compiler-specific optimizations. Packaged binaries must stay portable:
# -march=native bakes in the build host's ISA (SIGILL on other machines), so
# it is opt-in via BITCRACK_NATIVE for local builds. -ffast-math is gone:
# this is integer/crypto code where it buys nothing and breaks FP semantics.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(BitCrackCore PRIVATE
        -funroll-loops
        -Wno-deprecated-declarations
        $<$<BOOL:${BITCRACK_NATIVE}>:-march=native>
    )
endif()

# Suppress OpenSSL deprecation warnings on MSVC
if(MSVC)
    target_compile_definitions(BitCrackCore PRIVATE OPENSSL_API_COMPAT=0x10100000L)
endif()

# No OpenMP: CPU parallelism is std::thread (BitCrackEngine), and no source
# uses OpenMP. Linking it anyway only added a runtime dependency
# (libgomp / libomp.so, which an Android build would have to ship).

# Set properties
set_target_properties(BitCrackCore PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

# Ensure MSVC generates a proper PDB file name/path rather than an IntDir-only
# string that can be misinterpreted by MSBuild as a directory. This prevents the
# 'Copy' task in MSBuild attempting to copy a directory (which fails with MSB3025).
if(MSVC)
    set_target_properties(BitCrackCore PROPERTIES
        COMPILE_PDB_NAME BitCrackCore
        COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/src/$<CONFIG>"
    )
endif()