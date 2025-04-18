cmake_minimum_required(VERSION 3.15)

# Project declaration 
project(SC_CVar_Utility 
        VERSION 0.1.0
        DESCRIPTION "Star Citizen CVar Utility"
        LANGUAGES C CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# Set up cross-compilation for Windows when using MinGW
if(CMAKE_C_COMPILER MATCHES ".*mingw.*" OR CMAKE_CXX_COMPILER MATCHES ".*mingw.*")
    message(STATUS "Cross-compiling for Windows using MinGW")
    # Force Windows system for cross-compilation
    set(CMAKE_SYSTEM_NAME Windows)
    # Force WIN32 to be defined since we're targeting Windows
    set(WIN32 TRUE)
elseif(NOT WIN32)
    message(FATAL_ERROR "This project is only supported on Windows or with MinGW cross-compiler")
endif()

# Check for MinGW
if(MINGW)
    message(STATUS "Building with MinGW")
    # MinGW-specific flags
    add_compile_options(-Wall -Wextra)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Target Windows 7 or later
    
    # Add linking flag for proper DLL export with MinGW
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--enable-auto-import")
else()
    message(WARNING "This project is configured for MinGW, other compilers may not work correctly")
endif()

# Define output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# First build MinHook as a static library
# Copy MinHook sources from the specified location
set(MINHOOK_SRC_DIR "${CMAKE_HOME_DIRECTORY}/minhook")
set(MINHOOK_ORIGINAL_DIR "$ENV{HOME}/dev/srev/minhook")

# Create directory if it doesn't exist
file(MAKE_DIRECTORY ${MINHOOK_SRC_DIR})
file(MAKE_DIRECTORY ${MINHOOK_SRC_DIR}/hde)

# Copy MinHook files
file(GLOB MINHOOK_ROOT_FILES ${MINHOOK_ORIGINAL_DIR}/*.c ${MINHOOK_ORIGINAL_DIR}/*.h)
file(GLOB MINHOOK_HDE_FILES ${MINHOOK_ORIGINAL_DIR}/hde/*.c ${MINHOOK_ORIGINAL_DIR}/hde/*.h)

foreach(file ${MINHOOK_ROOT_FILES})
    get_filename_component(filename ${file} NAME)
    configure_file(${file} ${MINHOOK_SRC_DIR}/${filename} COPYONLY)
endforeach()

foreach(file ${MINHOOK_HDE_FILES})
    get_filename_component(filename ${file} NAME)
    configure_file(${file} ${MINHOOK_SRC_DIR}/hde/${filename} COPYONLY)
endforeach()

# Define MinHook library sources
set(MINHOOK_SOURCES
    ${MINHOOK_SRC_DIR}/buffer.c
    ${MINHOOK_SRC_DIR}/hook.c
    ${MINHOOK_SRC_DIR}/trampoline.c
    ${MINHOOK_SRC_DIR}/hde/hde32.c
    ${MINHOOK_SRC_DIR}/hde/hde64.c
)

# Create MinHook static library
add_library(minhook STATIC ${MINHOOK_SOURCES})
target_include_directories(minhook PRIVATE 
    ${MINHOOK_SRC_DIR}
    ${MINHOOK_SRC_DIR}/hde
)
target_compile_definitions(minhook PRIVATE
    _CRT_SECURE_NO_WARNINGS
)
set_target_properties(minhook PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

# Main SC_CVar_Utility DLL
# Define sources for the main project
set(SC_CVAR_SOURCES
    dllmain.cpp
    CVarManager.cpp
    Injector.cpp
    pch.cpp
)

# Create the DLL
add_library(${PROJECT_NAME} SHARED ${SC_CVAR_SOURCES})

# Set output name
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME SC_CVar_Utility
    PREFIX ""  # No 'lib' prefix for the DLL
)

# Define Windows-specific properties for DLL
set_target_properties(${PROJECT_NAME} PROPERTIES
    DEFINE_SYMBOL "BUILDING_DLL"
    WINDOWS_EXPORT_ALL_SYMBOLS ON
)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MINHOOK_SRC_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/libs
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    minhook
    comdlg32  # Common dialog library
    shlwapi   # Add Shell Lightweight API library for PathCombineW, PathFindFileNameW, etc.
)

# Compiler definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE
    WIN32
    _WINDOWS
    _USRDLL
    NOMINMAX  # Prevent Windows.h from defining min/max macros
    _CRT_SECURE_NO_WARNINGS
)

# Add compiler flags to handle C++17 features and silence specific warnings
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE
        -std=c++17
        # Add any other compiler flags as needed
    )
endif()

# Force include our compatibility header
target_compile_options(${PROJECT_NAME} PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/compat.h"
)

# Install rules (optional)
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

# Add a message to show how to build
message(STATUS "Configure completed. Run 'cmake --build .' to build the project.")

