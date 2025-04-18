# Toolchain file for cross-compiling to Windows using MinGW on macOS
# Specify the target system
set(CMAKE_SYSTEM_NAME Windows)

# Specify the cross compilers
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

# Disable macOS-specific compiler flags
set(CMAKE_OSX_ARCHITECTURES "" CACHE INTERNAL "")
set(CMAKE_OSX_DEPLOYMENT_TARGET "" CACHE INTERNAL "")
set(CMAKE_OSX_SYSROOT "" CACHE INTERNAL "")

# Where to look for the target environment
set(CMAKE_FIND_ROOT_PATH /opt/local/x86_64-w64-mingw32)

# Search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Set the target environment
set(CMAKE_CROSSCOMPILING TRUE)
set(WIN32 TRUE)
set(MINGW TRUE)

# Set additional compiler flags if needed
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libgcc" CACHE STRING "C flags")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++" CACHE STRING "C++ flags")
