if(NOT GUI_AVAILABLE)
    return()
endif()

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(GUI_SOURCES
    MainWindow.cpp
    ${CMAKE_SOURCE_DIR}/include/MainWindow.h
)

# Library type. BitCrackCore, NetworkLayer and GPUKernels are STATIC libraries
# that the executable links directly. Building the GUI as a shared library that
# also links them puts a second copy of every core global (Logger state,
# function-local statics, ...) into the process. On Linux the ELF loader then
# runs both copies' static destructors on the same interposed objects at exit,
# so even `--version` aborted with "double free" (exit 134), and ASan reported
# ODR violations. As a static library the GUI is linked into the executable
# once, together with exactly one copy of the core.
#
# Windows keeps the DLL by default: scripts/package_windows.ps1 packages
# BitCrackGUI.dll and runs windeployqt on it. (A DLL there still carries its own
# private copy of the core, which the Windows loader keeps separate rather than
# merging, so it does not crash, but it is the same duplication.
# -DBITCRACK_GUI_SHARED=OFF builds it statically there as well.)
if(WIN32)
    set(_bitcrack_gui_shared_default ON)
else()
    set(_bitcrack_gui_shared_default OFF)
endif()
option(BITCRACK_GUI_SHARED "Build BitCrackGUI as a shared library (default: ON on Windows only)" ${_bitcrack_gui_shared_default})

if(BITCRACK_GUI_SHARED)
    add_library(BitCrackGUI SHARED ${GUI_SOURCES})
else()
    add_library(BitCrackGUI STATIC ${GUI_SOURCES})
    # No dllexport/dllimport decoration for a static library (see BitCrackGUIExport.h).
    target_compile_definitions(BitCrackGUI PUBLIC BITCRACKGUI_STATIC)
endif()

target_include_directories(BitCrackGUI
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}
)

set(_qt_prefix Qt${BITCRACK_QT_VERSION})

target_link_libraries(BitCrackGUI
    PRIVATE
        ${_qt_prefix}::Core
        ${_qt_prefix}::Widgets
        ${_qt_prefix}::Network
    BitCrackCore
    NetworkLayer
        GPUKernels
)

target_compile_definitions(BitCrackGUI PRIVATE BUILDING_BITCRACKGUI)

if(TARGET OpenSSL::SSL)
    target_link_libraries(BitCrackGUI PRIVATE OpenSSL::SSL OpenSSL::Crypto)
elseif(OPENSSL_LIBRARIES)
    target_link_libraries(BitCrackGUI PRIVATE ${OPENSSL_LIBRARIES})
endif()

if(OPENSSL_INCLUDE_DIR)
    target_include_directories(BitCrackGUI PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

target_compile_definitions(BitCrackGUI PRIVATE GUI_AVAILABLE)

# Ensure automoc sees the Q_OBJECT in MainWindow.h even when the header is in include/
set_source_files_properties(${CMAKE_SOURCE_DIR}/include/MainWindow.h PROPERTIES COMPILE_DEFINITIONS "GUI_AVAILABLE")
set_source_files_properties(${CMAKE_SOURCE_DIR}/include/MainWindow.h PROPERTIES SKIP_AUTOMOC FALSE)

set_target_properties(BitCrackGUI PROPERTIES
    AUTOMOC TRUE
    AUTORCC TRUE
    AUTOUIC TRUE
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG>
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG>
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$<CONFIG>
)

# Copy BitCrackGUI to dist directory if BITCRACK_COPY_BUILD_TO_DIST is enabled
if(BITCRACK_COPY_BUILD_TO_DIST AND WIN32)
    set(DIST_ROOT "${CMAKE_SOURCE_DIR}/dist")
    set(DIST_GUI_DIR "${DIST_ROOT}/windows/gui")
    
    add_custom_command(TARGET BitCrackGUI POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DIST_GUI_DIR}"
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:BitCrackGUI> "${DIST_GUI_DIR}"
        COMMENT "Copy BitCrackGUI.dll to ${DIST_GUI_DIR}"
    )
endif()
