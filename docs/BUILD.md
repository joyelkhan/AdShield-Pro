# AdShield Pro Ultra - Build Guide

## Prerequisites

### Common Requirements
- C++20 compatible compiler
- CMake 3.16 or higher
- Git

### Platform-Specific Requirements

#### Windows
- Visual Studio 2019 or later (with C++ workload)
- OR MinGW with GCC 10+
- OpenSSL development libraries
- libcurl development libraries

#### Linux
- GCC 10+ or Clang 11+
- libssl-dev
- libcurl4-openssl-dev
- build-essential

#### macOS
- Xcode 12 or later
- Homebrew (recommended)
- OpenSSL (via Homebrew)
- libcurl (via Homebrew)

## Installation of Dependencies

### Windows (Visual Studio)

```powershell
# Using vcpkg (recommended)
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\vcpkg integrate install
.\vcpkg install openssl:x64-windows curl:x64-windows

# Or using pre-built binaries
# Download from https://slproweb.com/products/Win32OpenSSL.html
# Download from https://curl.se/download.html
```

### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libcurl4-openssl-dev \
    pkg-config
```

### Linux (Fedora/RHEL)

```bash
sudo dnf install -y \
    gcc-c++ \
    cmake \
    git \
    openssl-devel \
    libcurl-devel \
    pkgconfig
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake openssl curl
```

## Building from Source

### Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/adshield-pro-ultra.git
cd adshield-pro-ultra

# Build
mkdir build && cd build
cmake ..
cmake --build . --config Release

# Install
sudo cmake --install .
```

### Detailed Build Instructions

#### Windows (Visual Studio)

```powershell
# Create build directory
mkdir build
cd build

# Configure with Visual Studio 2019
cmake -G "Visual Studio 16 2019" -A x64 ..

# Build
cmake --build . --config Release

# Install (optional)
cmake --install . --config Release
```

#### Windows (MinGW)

```bash
# Create build directory
mkdir build
cd build

# Configure with MinGW
cmake -G "MinGW Makefiles" ..

# Build
cmake --build . --config Release

# Install
cmake --install .
```

#### Linux

```bash
# Create build directory
mkdir build && cd build

# Configure
cmake -DCMAKE_BUILD_TYPE=Release ..

# Build
cmake --build . -j$(nproc)

# Install
sudo cmake --install .
```

#### macOS

```bash
# Create build directory
mkdir build && cd build

# Configure with OpenSSL from Homebrew
cmake -DOPENSSL_DIR=$(brew --prefix openssl) \
       -DCMAKE_BUILD_TYPE=Release ..

# Build
cmake --build . -j$(sysctl -n hw.ncpu)

# Install
sudo cmake --install .
```

### Build Options

```bash
# Debug build with symbols
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release build with optimizations
cmake -DCMAKE_BUILD_TYPE=Release ..

# Custom installation prefix
cmake -DCMAKE_INSTALL_PREFIX=/opt/adshield ..

# Disable tests
cmake -DBUILD_TESTS=OFF ..

# Enable verbose output
cmake --build . --verbose
```

## Building Using Scripts

### Linux/macOS

```bash
# Make script executable
chmod +x scripts/build.sh

# Build with default (release) configuration
./scripts/build.sh

# Build with debug configuration
./scripts/build.sh debug
```

### Windows

```powershell
# Run build script
.\scripts\build.bat

# Or with debug configuration
.\scripts\build.bat debug
```

## Testing

### Running Tests

```bash
cd build

# Run all tests
ctest --output-on-failure

# Run specific test
ctest -R test_name --output-on-failure

# Run with verbose output
ctest --verbose
```

### Building Tests

```bash
# Tests are built by default, but can be explicitly enabled
cmake -DBUILD_TESTS=ON ..
cmake --build .
```

## Installation

### System-Wide Installation

```bash
# Linux/macOS
sudo cmake --install .

# Windows (as Administrator)
cmake --install .
```

### Custom Installation Path

```bash
cmake -DCMAKE_INSTALL_PREFIX=/custom/path ..
cmake --build .
cmake --install .
```

### Portable Installation

```bash
# Create portable directory
mkdir adshield-portable
cd adshield-portable

# Build with custom prefix
cmake -DCMAKE_INSTALL_PREFIX=. ..
cmake --build .
cmake --install .

# Run directly
./bin/adshield-pro
```

## Troubleshooting

### CMake Configuration Issues

**Error: "Could not find OpenSSL"**
```bash
# Specify OpenSSL path explicitly
cmake -DOPENSSL_DIR=/path/to/openssl ..

# Or on macOS with Homebrew
cmake -DOPENSSL_DIR=$(brew --prefix openssl) ..
```

**Error: "Could not find CURL"**
```bash
# Specify CURL path explicitly
cmake -DCURL_DIR=/path/to/curl ..

# Or on macOS with Homebrew
cmake -DCURL_DIR=$(brew --prefix curl) ..
```

### Build Errors

**"C++20 not supported"**
- Update compiler to GCC 10+, Clang 11+, or MSVC 2019+
- Or specify compiler explicitly: `cmake -DCMAKE_CXX_COMPILER=g++-10 ..`

**"Permission denied" on Linux**
- Run with `sudo` for system-wide installation
- Or use custom prefix: `cmake -DCMAKE_INSTALL_PREFIX=$HOME/.local ..`

### Runtime Issues

**"Cannot find shared libraries"**
```bash
# Set library path
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Or on macOS
export DYLD_LIBRARY_PATH=/usr/local/lib:$DYLD_LIBRARY_PATH
```

## Cross-Compilation

### Building for ARM64 on x86_64

```bash
# Linux ARM64
cmake -DCMAKE_SYSTEM_NAME=Linux \
       -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
       -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
       -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ ..

# Windows ARM64
cmake -G "Visual Studio 16 2019" -A ARM64 ..
```

## Performance Optimization

### Release Build Optimizations

```bash
cmake -DCMAKE_BUILD_TYPE=Release \
       -DCMAKE_CXX_FLAGS_RELEASE="-O3 -march=native" ..
```

### Link-Time Optimization (LTO)

```bash
cmake -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON ..
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Build

on: [push, pull_request]

jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: |
          # Platform-specific installation
      - name: Build
        run: |
          mkdir build
          cd build
          cmake ..
          cmake --build . --config Release
      - name: Test
        run: |
          cd build
          ctest --output-on-failure
```

## Packaging

### Creating Distribution Packages

#### Linux (DEB)

```bash
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
cmake --build .
cpack -G DEB
```

#### Linux (RPM)

```bash
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
cmake --build .
cpack -G RPM
```

#### Windows (ZIP)

```powershell
cmake --build . --config Release
cpack -G ZIP
```

#### macOS (DMG)

```bash
cmake ..
cmake --build .
cpack -G DragNDrop
```

## Support

For build issues, please:
1. Check this guide
2. Review CMakeLists.txt
3. Check platform-specific documentation
4. Open an issue on GitHub with:
   - OS and version
   - Compiler and version
   - CMake version
   - Error messages
   - Steps to reproduce
