# Networking and P2P library
set(_NETWORK_SOURCE_CANDIDATES
    NetworkManager.cpp
    PuzzleSolveTrust.cpp
    P2PNode.cpp
    RangeValidator.cpp
    ConsensusEngine.cpp
    MessageHandler.cpp
    ContributionSigner.cpp
    WireCodec.cpp
    ChunkClaimBook.cpp
    PeerDiscovery.cpp
    RewardSystem.cpp
    WorkCoordinator.cpp
    P2PKeyspaceManager.cpp
    NodeStats.cpp
    NodeApi.cpp
)

set(NETWORK_SOURCES)
foreach(SRC ${_NETWORK_SOURCE_CANDIDATES})
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${SRC})
        list(APPEND NETWORK_SOURCES ${SRC})
    else()
        message(WARNING "Network source missing: ${CMAKE_CURRENT_SOURCE_DIR}/${SRC}")
    endif()
endforeach()

# If none exist, create dummy
if(NOT NETWORK_SOURCES)
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dummy_network.cpp "#include <stddef.h>\nint __network_dummy = 0;\n")
    list(APPEND NETWORK_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/dummy_network.cpp)
endif()

set(_NETWORK_HEADER_CANDIDATES
    ${CMAKE_SOURCE_DIR}/include/NetworkManager.h
    ${CMAKE_SOURCE_DIR}/include/P2PNode.h
    ${CMAKE_SOURCE_DIR}/include/RangeValidator.h
    ${CMAKE_SOURCE_DIR}/include/ConsensusEngine.h
    ${CMAKE_SOURCE_DIR}/include/MessageHandler.h
    ${CMAKE_SOURCE_DIR}/include/ContributionSigner.h
    ${CMAKE_SOURCE_DIR}/include/WireCodec.h
    ${CMAKE_SOURCE_DIR}/include/ChunkClaimBook.h
    ${CMAKE_SOURCE_DIR}/include/PeerDiscovery.h
    ${CMAKE_SOURCE_DIR}/include/RewardSystem.h
    ${CMAKE_SOURCE_DIR}/include/NetworkProtocol.h
    ${CMAKE_SOURCE_DIR}/include/WorkCoordinator.h
    ${CMAKE_SOURCE_DIR}/include/P2PKeyspaceManager.h
    ${CMAKE_SOURCE_DIR}/include/NodeStats.h
    ${CMAKE_SOURCE_DIR}/include/NodeApi.h
)

set(NETWORK_HEADERS)
foreach(HDR ${_NETWORK_HEADER_CANDIDATES})
    if(EXISTS ${HDR})
        list(APPEND NETWORK_HEADERS ${HDR})
    endif()
endforeach()

# Create the network library
add_library(NetworkLayer STATIC 
    ${NETWORK_SOURCES}
    ${NETWORK_HEADERS}
)

# Include directories
target_include_directories(NetworkLayer PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Link with core library
target_link_libraries(NetworkLayer BitCrackCore)

# Link threading libraries
target_link_libraries(NetworkLayer ${CMAKE_THREAD_LIBS_INIT})

# Link OpenSSL for cryptographic operations
find_package(OpenSSL REQUIRED)
target_link_libraries(NetworkLayer OpenSSL::SSL OpenSSL::Crypto)

# Platform-specific networking libraries
if(WIN32)
    target_link_libraries(NetworkLayer ws2_32 wsock32 iphlpapi)
elseif(UNIX)
    # No additional libraries needed on Unix systems
endif()

# Find and link optional UPnP library for NAT traversal
find_library(UPNP_LIBRARY miniupnpc)
if(UPNP_LIBRARY)
    target_link_libraries(NetworkLayer ${UPNP_LIBRARY})
    target_compile_definitions(NetworkLayer PRIVATE UPNP_AVAILABLE)
    message(STATUS "UPnP library found - NAT traversal enabled")
else()
    message(STATUS "UPnP library not found - manual port forwarding required")
endif()

# Optional: Find and link Boost.Asio or standalone asio for async networking
find_package(Boost QUIET COMPONENTS system)
set(_asio_available OFF)
if(Boost_FOUND)
    target_link_libraries(NetworkLayer ${Boost_LIBRARIES})
    target_include_directories(NetworkLayer PRIVATE ${Boost_INCLUDE_DIRS})
    target_compile_definitions(NetworkLayer PRIVATE BOOST_ASIO_AVAILABLE)
    set(_asio_available ON)
    message(STATUS "Boost.Asio found - using Boost networking")
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
        target_include_directories(NetworkLayer PRIVATE ${ASIO_INCLUDE_DIR})
        target_compile_definitions(NetworkLayer PRIVATE ASIO_STANDALONE ASIO_AVAILABLE)
        set(_asio_available ON)
        message(STATUS "Standalone ASIO available - using ASIO networking")
    else()
        message(STATUS "Neither Boost.Asio nor standalone ASIO found - using basic sockets")
    endif()
endif()

# JSON library for message serialization
if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(NetworkLayer nlohmann_json::nlohmann_json)
    target_compile_definitions(NetworkLayer PRIVATE JSON_AVAILABLE)
    message(STATUS "nlohmann/json target available - using JSON serialization")
else()
    find_package(nlohmann_json QUIET)
    if(nlohmann_json_FOUND)
    target_link_libraries(NetworkLayer nlohmann_json::nlohmann_json)
    target_compile_definitions(NetworkLayer PRIVATE JSON_AVAILABLE)
    message(STATUS "nlohmann/json found - using JSON serialization")
    else()
        message(STATUS "nlohmann/json not found - using basic string serialization")
    endif()
endif()

# Set properties
set_target_properties(NetworkLayer PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

if(MSVC)
    set_target_properties(NetworkLayer PROPERTIES
        COMPILE_PDB_NAME NetworkLayer
        COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/network/$<CONFIG>"
    )
endif()

# Compiler optimizations (-ffast-math removed: integer/crypto code gains
# nothing from it and it breaks FP edge-case semantics)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(NetworkLayer PRIVATE
        -O2
    )
elseif(MSVC)
    target_compile_options(NetworkLayer PRIVATE
        $<$<CONFIG:Debug>:/Od>
        $<$<CONFIG:Release>:/O2 /fp:fast>
        $<$<CONFIG:RelWithDebInfo>:/O2 /fp:fast>
    )
endif()

# Enable network debugging in debug builds
target_compile_definitions(NetworkLayer PRIVATE 
    $<$<CONFIG:Debug>:NETWORK_DEBUG>
)
# Short commit for the stats API (/status "commit"). A source tarball
# can carry it in a top-level .commit file; otherwise ask git at configure time.
set(BCD_BUILD_COMMIT "unknown")
if(EXISTS ${CMAKE_SOURCE_DIR}/.commit)
    file(STRINGS ${CMAKE_SOURCE_DIR}/.commit _bcd_commit LIMIT_COUNT 1)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/.commit)
    if(_bcd_commit)
        set(BCD_BUILD_COMMIT "${_bcd_commit}")
    endif()
else()
    find_package(Git QUIET)
    if(GIT_FOUND)
        execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short=12 HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE _bcd_commit OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE _bcd_git_rc ERROR_QUIET)
        if(_bcd_git_rc EQUAL 0 AND _bcd_commit)
            set(BCD_BUILD_COMMIT "${_bcd_commit}")
        endif()
    endif()
endif()
string(REGEX REPLACE "[^0-9A-Za-z._-]" "" BCD_BUILD_COMMIT "${BCD_BUILD_COMMIT}")
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/NodeStats.cpp)
    set_source_files_properties(NodeStats.cpp PROPERTIES COMPILE_DEFINITIONS "BCD_BUILD_COMMIT=\"${BCD_BUILD_COMMIT}\"")
endif()
