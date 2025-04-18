# Makefile for DataCoreDumper project

# Default build type
BUILD_TYPE ?= Debug

# Directories
BUILD_DIR = build

.PHONY: all build build-release clean

# Default target
all: build

# Build with Debug configuration
build:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -G Ninja \
		-DCMAKE_TOOLCHAIN_FILE=../mingw-toolchain.cmake \
		-DCMAKE_BUILD_TYPE=Debug
	cd $(BUILD_DIR) && ninja

# Build with Release configuration
build-release:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -G Ninja \
		-DCMAKE_TOOLCHAIN_FILE=../mingw-toolchain.cmake \
		-DCMAKE_BUILD_TYPE=Release
	cd $(BUILD_DIR) && ninja

# Clean build directory
clean:
	rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned."
