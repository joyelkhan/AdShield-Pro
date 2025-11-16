#!/bin/bash

# AdShield Pro Ultra - Build Script for Linux/macOS
# Usage: ./build.sh [debug|release]

set -e

BUILD_TYPE=${1:-release}
BUILD_DIR="build"
INSTALL_PREFIX="/usr/local"

echo "================================"
echo "AdShield Pro Ultra Build Script"
echo "================================"
echo "Build Type: $BUILD_TYPE"
echo "Build Directory: $BUILD_DIR"
echo ""

# Check for required tools
echo "Checking for required tools..."
if ! command -v cmake &> /dev/null; then
    echo "ERROR: CMake not found. Please install CMake 3.16 or higher."
    exit 1
fi

if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
    echo "ERROR: C++ compiler not found. Please install GCC or Clang."
    exit 1
fi

# Check for required libraries
echo "Checking for required libraries..."
if ! pkg-config --exists openssl; then
    echo "ERROR: OpenSSL not found. Please install libssl-dev."
    exit 1
fi

if ! pkg-config --exists libcurl; then
    echo "ERROR: libcurl not found. Please install libcurl4-openssl-dev."
    exit 1
fi

echo "All dependencies found!"
echo ""

# Create build directory
if [ ! -d "$BUILD_DIR" ]; then
    echo "Creating build directory..."
    mkdir -p "$BUILD_DIR"
fi

# Configure
echo "Configuring CMake..."
cd "$BUILD_DIR"
cmake -DCMAKE_BUILD_TYPE=$(echo $BUILD_TYPE | tr a-z A-Z) \
       -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
       ..

# Build
echo "Building AdShield Pro Ultra..."
cmake --build . --config $(echo $BUILD_TYPE | tr a-z A-Z) -j$(nproc)

echo ""
echo "Build completed successfully!"
echo ""
echo "To install, run: sudo cmake --install ."
echo "To run tests, run: ctest --output-on-failure"
