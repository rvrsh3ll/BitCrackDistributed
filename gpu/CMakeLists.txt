# GPU kernels and management library
set(_GPU_SOURCE_CANDIDATES
    GPUManager.cpp
    CUDAKernel.cpp
    OpenCLKernel.cpp
    GPUProbe.c
)

# Headers optional
set(_GPU_HEADER_CANDIDATES
    ${CMAKE_SOURCE_DIR}/include/GPUManager.h
    ${CMAKE_SOURCE_DIR}/include/CUDAKernel.h
    ${CMAKE_SOURCE_DIR}/include/OpenCLKernel.h
)

set(GPU_HEADERS)
foreach(HDR ${_GPU_HEADER_CANDIDATES})
    if(EXISTS ${HDR})
        list(APPEND GPU_HEADERS ${HDR})
    endif()
endforeach()

# Filter existing GPU sources
set(GPU_SOURCES)
foreach(SRC ${_GPU_SOURCE_CANDIDATES})
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${SRC})
        list(APPEND GPU_SOURCES ${SRC})
    else()
        message(WARNING "GPU source missing: ${CMAKE_CURRENT_SOURCE_DIR}/${SRC}")
    endif()
endforeach()

# If any C sources are present, ensure the C language is enabled and
# mark them to be compiled as C (prevents CMake from treating them as 'None')
set(_GPU_HAS_C_SOURCES OFF)
foreach(SRC ${GPU_SOURCES})
    if(SRC MATCHES ".*\\.c$")
        set(_GPU_HAS_C_SOURCES ON)
        # Set the source file property to C to force correct compilation
        set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/${SRC} PROPERTIES LANGUAGE C)
    endif()
endforeach()
if(_GPU_HAS_C_SOURCES)
    enable_language(C)
endif()

# If none exist, create dummy
if(NOT GPU_SOURCES)
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dummy_gpu.cpp "#include <stddef.h>\nint __gpu_dummy = 0;\n")
    list(APPEND GPU_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/dummy_gpu.cpp)
endif()

# CUDA kernel files
set(CUDA_KERNEL_SOURCES "")
if(CUDA_AVAILABLE)
    set(_CUDA_KERNEL_CANDIDATES
        kernels/bitcrack.cu
        kernels/secp256k1.cu
        kernels/hash160.cu
        kernels/ripemd160.cu
        kernels/sha256.cu
    )
    foreach(KERNEL ${_CUDA_KERNEL_CANDIDATES})
        if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${KERNEL})
            list(APPEND CUDA_KERNEL_SOURCES ${KERNEL})
        else()
            message(WARNING "CUDA kernel missing: ${CMAKE_CURRENT_SOURCE_DIR}/${KERNEL}")
        endif()
    endforeach()
endif()

# OpenCL kernel files  
set(OPENCL_KERNEL_SOURCES "")
if(OPENCL_AVAILABLE)
    set(OPENCL_KERNEL_SOURCES
        kernels/bitcrack.cl
        kernels/secp256k1.cl
        kernels/hash160.cl
        kernels/ripemd160.cl
        kernels/sha256.cl
    )
endif()

# Create the GPU library
add_library(GPUKernels STATIC 
    ${GPU_SOURCES}
    ${GPU_HEADERS}
)

# If gpu_probe.c exists but OpenCL wasn't found, ensure it's still compiled
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/GPUProbe.c AND NOT "${GPU_SOURCES}" STREQUAL "")
    # Already appended above; ensure the language is set
    set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/GPUProbe.c PROPERTIES LANGUAGE C)
endif()

# Include directories
target_include_directories(GPUKernels PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# CUDA configuration
if(CUDA_AVAILABLE)
    # Enable CUDA language for the library
    set_property(TARGET GPUKernels PROPERTY CUDA_STANDARD 17)
    set_property(TARGET GPUKernels PROPERTY CUDA_STANDARD_REQUIRED ON)
    
    # Add CUDA kernel sources
    target_sources(GPUKernels PRIVATE ${CUDA_KERNEL_SOURCES})
    
    # CUDA compile flags
    # Prefer PTX (virtual) for forward-compatibility and include recent SMs.
    # Avoid hard-binding to a single SASS that might not match end-user GPUs (e.g., RTX 5080).
    # This builds PTX for multiple targets so newer drivers JIT appropriately.
    set_property(TARGET GPUKernels PROPERTY CUDA_ARCHITECTURES "89-virtual;90-virtual;100-virtual")
    
    # Link CUDA driver API only (avoid CUDA Runtime API / cudart).
    # On some systems, cudart entrypoints (cudaGetDeviceCount/cudaSetDevice) can hard-terminate
    # the process when driver/runtime mismatch occurs. Using the driver API (cuInit/cuDeviceGetCount)
    # is typically more robust.
    find_package(CUDAToolkit REQUIRED)
    set_property(TARGET GPUKernels PROPERTY CUDA_RUNTIME_LIBRARY None)
    target_link_libraries(GPUKernels CUDA::cuda_driver)
    target_compile_definitions(GPUKernels PRIVATE CUDA_AVAILABLE)
    
    message(STATUS "CUDA kernels will be compiled for multiple architectures")
endif()

# OpenCL configuration
if(OPENCL_AVAILABLE)
    target_link_libraries(GPUKernels ${OpenCL_LIBRARIES})
    target_include_directories(GPUKernels PRIVATE ${OpenCL_INCLUDE_DIRS})
    target_compile_definitions(GPUKernels PRIVATE OPENCL_AVAILABLE)
    
    # Copy OpenCL kernel files to build directory if they exist; otherwise warn but continue
    set(_ANY_OPENCL_KERNEL_FOUND OFF)
    foreach(KERNEL_FILE ${OPENCL_KERNEL_SOURCES})
        if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${KERNEL_FILE})
            get_filename_component(_dst_dir ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL_FILE} DIRECTORY)
            file(MAKE_DIRECTORY ${_dst_dir})
            configure_file(
                ${CMAKE_CURRENT_SOURCE_DIR}/${KERNEL_FILE}
                ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL_FILE}
                COPYONLY
            )
            set(_ANY_OPENCL_KERNEL_FOUND ON)
        else()
            message(WARNING "OpenCL kernel not found: ${CMAKE_CURRENT_SOURCE_DIR}/${KERNEL_FILE} (skipping copy)")
        endif()
    endforeach()

    if(_ANY_OPENCL_KERNEL_FOUND)
        message(STATUS "OpenCL kernels will be loaded at runtime")
    else()
        message(STATUS "No OpenCL kernel sources present; runtime will expect external kernel files")
    endif()
endif()

# Link with core library
target_link_libraries(GPUKernels BitCrackCore)

# Set properties
set_target_properties(GPUKernels PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

if(MSVC)
    set_target_properties(GPUKernels PROPERTIES
        COMPILE_PDB_NAME GPUKernels
        COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/gpu/$<CONFIG>"
    )
endif()

# Optimization flags (scoped per language to avoid leaking MSVC flags into NVCC)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(GPUKernels PRIVATE 
        $<$<COMPILE_LANGUAGE:CXX>:$<$<CONFIG:Debug>:-O0> $<$<CONFIG:Release>:-O3 -ffast-math -funroll-loops> $<$<CONFIG:RelWithDebInfo>:-O3 -ffast-math -funroll-loops>>
        $<$<COMPILE_LANGUAGE:C>:$<$<CONFIG:Debug>:-O0> $<$<CONFIG:Release>:-O3 -ffast-math -funroll-loops> $<$<CONFIG:RelWithDebInfo>:-O3 -ffast-math -funroll-loops>>
        # Keep CUDA flags minimal in Debug; enable fastmath in Release configs only
        $<$<COMPILE_LANGUAGE:CUDA>:$<$<CONFIG:Debug>:-g> $<$<CONFIG:Release>:-O3 --use_fast_math> $<$<CONFIG:RelWithDebInfo>:-O3 --use_fast_math>>
    )
elseif(MSVC)
    target_compile_options(GPUKernels PRIVATE
        # Apply only to host compilers (C/C++). Use appropriate optimization per config.
        $<$<COMPILE_LANGUAGE:CXX>:$<$<CONFIG:Debug>:/Od> $<$<CONFIG:Release>:/O2 /fp:fast> $<$<CONFIG:RelWithDebInfo>:/O2 /fp:fast>>
        $<$<COMPILE_LANGUAGE:C>:$<$<CONFIG:Debug>:/Od> $<$<CONFIG:Release>:/O2 /fp:fast> $<$<CONFIG:RelWithDebInfo>:/O2 /fp:fast>>
        # Use CUDA-friendly flags for device compilation; only enable --use_fast_math in non-Debug configs
        $<$<COMPILE_LANGUAGE:CUDA>:$<$<CONFIG:Debug>:-G -g> $<$<CONFIG:Release>:-O3 --use_fast_math> $<$<CONFIG:RelWithDebInfo>:-O3 --use_fast_math>>
    )
    set_property(TARGET GPUKernels PROPERTY STATIC_LIBRARY_OPTIONS "/IGNORE:4006")
endif()

# Create kernels directory if it doesn't exist
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/kernels)