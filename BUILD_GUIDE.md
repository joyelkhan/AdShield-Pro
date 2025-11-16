# AdShield Pro v1.0 - Complete Build & Deployment Guide

**Author:** MD Abu Naser Khan

## 📋 Table of Contents
1. [Quick Start](#quick-start)
2. [System Requirements](#system-requirements)
3. [Building from Source](#building-from-source)
4. [Multi-Platform Builds](#multi-platform-builds)
5. [Testing & Analysis](#testing--analysis)
6. [Deployment](#deployment)
7. [Troubleshooting](#troubleshooting)

---

## 🚀 Quick Start

### Windows (PowerShell)
```powershell
cd "ADSGUARD ultra"
.\scripts\build_all_platforms.ps1 -Configuration Release
```

### Linux/macOS (Bash)
```bash
cd "ADSGUARD ultra"
chmod +x scripts/build_all_platforms.sh
./scripts/build_all_platforms.sh
```

---

## 📦 System Requirements

### Windows
- **OS**: Windows 10/11 (x64)
- **Compiler**: Visual Studio 2022 or MinGW
- **Tools**: CMake 3.20+, Git
- **Dependencies**: OpenSSL, libcurl, re2

### macOS
- **OS**: macOS 11+ (Intel/Apple Silicon)
- **Compiler**: Clang (Xcode 13+)
- **Tools**: CMake 3.20+, Homebrew
- **Dependencies**: OpenSSL, libcurl, re2

### Linux
- **OS**: Ubuntu 20.04+, Fedora 34+, Debian 11+
- **Compiler**: GCC 11+ or Clang 13+
- **Tools**: CMake 3.20+, build-essential
- **Dependencies**: libssl-dev, libcurl4-openssl-dev, libre2-dev

#### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    cmake \
    build-essential \
    libssl-dev \
    libcurl4-openssl-dev \
    libre2-dev \
    git
```

**Fedora/RHEL:**
```bash
sudo dnf install -y \
    cmake \
    gcc-c++ \
    openssl-devel \
    libcurl-devel \
    re2-devel \
    git
```

**macOS (Homebrew):**
```bash
brew install cmake openssl libcurl re2
```

---

## 🔨 Building from Source

### Step 1: Clone Repository
```bash
git clone https://github.com/yourusername/ADSGUARD-ultra.git
cd "ADSGUARD ultra"
```

### Step 2: Create Build Directory
```bash
mkdir -p build
cd build
```

### Step 3: Configure with CMake
```bash
# Release build (optimized)
cmake -DCMAKE_BUILD_TYPE=Release ..

# Debug build (with symbols)
cmake -DCMAKE_BUILD_TYPE=Debug ..

# With all optimizations
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="-O3 -march=native -flto" ..
```

### Step 4: Build
```bash
# Using make (Linux/macOS)
make -j$(nproc)

# Using Visual Studio (Windows)
cmake --build . --config Release -j 4

# Using Ninja (all platforms)
ninja
```

### Step 5: Install
```bash
sudo make install
# or
cmake --install . --prefix /usr/local
```

---

## 🌍 Multi-Platform Builds

### Automated Build Script

**Windows (PowerShell):**
```powershell
# Build for Windows only
.\scripts\build_all_platforms.ps1

# Build for all platforms (requires cross-compilers)
.\scripts\build_all_platforms.ps1 -All

# Skip tests
.\scripts\build_all_platforms.ps1 -SkipTests

# Skip analysis
.\scripts\build_all_platforms.ps1 -SkipAnalysis
```

**Linux/macOS (Bash):**
```bash
# Build for current platform
./scripts/build_all_platforms.sh

# Build for all platforms
./scripts/build_all_platforms.sh --all

# Skip tests
./scripts/build_all_platforms.sh --skip-tests

# Skip analysis
./scripts/build_all_platforms.sh --skip-analysis
```

### Cross-Compilation

#### Linux to Windows (MinGW)
```bash
cmake -DCMAKE_TOOLCHAIN_FILE=cmake/mingw.cmake \
      -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

#### macOS to Linux
```bash
cmake -DCMAKE_TOOLCHAIN_FILE=cmake/linux-cross.cmake \
      -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

---

## 🧪 Testing & Analysis

### Run Tests
```bash
cd build
ctest --output-on-failure
```

### Code Analysis
```bash
# Static analysis with clang-tidy
python3 scripts/analyze_codebase.py .

# Memory analysis with Valgrind (Linux)
valgrind --leak-check=full ./adsguard_ultra

# Performance profiling (Linux)
perf record -g ./adsguard_ultra
perf report
```

### Benchmarking
```bash
python3 scripts/performance_benchmark.py ./build/adsguard_ultra
```

---

## 📦 Deployment

### Creating Packages

**Linux (DEB/RPM):**
```bash
cd build
cpack -G "DEB;RPM"
```

**macOS (DMG):**
```bash
cd build
cpack -G "DragNDrop"
```

**Windows (NSIS/ZIP):**
```bash
cd build
cpack -G "NSIS;ZIP"
```

### Distribution

#### Linux
```bash
# Install from DEB
sudo dpkg -i adsguard-ultra-2.0.0-Linux.deb

# Install from RPM
sudo rpm -i adsguard-ultra-2.0.0-Linux.rpm
```

#### macOS
```bash
# Mount DMG and install
hdiutil mount adsguard-ultra-2.0.0-Darwin.dmg
# Drag ADSGuard to Applications folder
```

#### Windows
```powershell
# Run NSIS installer
.\adsguard-ultra-2.0.0-win64.exe

# Or extract ZIP
Expand-Archive adsguard-ultra-2.0.0-win64.zip -DestinationPath "C:\Program Files"
```

---

## 🔧 Troubleshooting

### CMake Not Found
```bash
# Install CMake
# Ubuntu/Debian
sudo apt-get install cmake

# macOS
brew install cmake

# Windows (Chocolatey)
choco install cmake
```

### Missing Dependencies
```bash
# Check what's missing
cmake --debug-output

# Install missing packages
# See "System Requirements" section above
```

### Build Failures

**OpenSSL Not Found:**
```bash
# Linux
export OPENSSL_DIR=/usr/lib/ssl

# macOS
export OPENSSL_DIR=$(brew --prefix openssl)

# Windows
set OPENSSL_DIR=C:\OpenSSL
```

**libcurl Not Found:**
```bash
# Linux
export CURL_DIR=/usr/lib/x86_64-linux-gnu

# macOS
export CURL_DIR=$(brew --prefix curl)
```

### Performance Issues

1. **Enable LTO (Link Time Optimization):**
   ```bash
   cmake -DCMAKE_CXX_FLAGS="-flto" ..
   ```

2. **Use Native Architecture:**
   ```bash
   cmake -DCMAKE_CXX_FLAGS="-march=native" ..
   ```

3. **Profile with Perf:**
   ```bash
   perf record -g ./adsguard_ultra
   perf report
   ```

---

## 📊 Build Artifacts

After successful build, you'll find:

```
dist/
├── linux/
│   └── adsguard_ultra
├── macos/
│   └── adsguard_ultra
└── windows/
    └── adsguard_ultra.exe

build/
├── linux/
│   ├── adsguard-ultra-2.0.0-Linux.deb
│   ├── adsguard-ultra-2.0.0-Linux.rpm
│   └── adsguard-ultra-2.0.0-Linux.tar.gz
├── macos/
│   ├── adsguard-ultra-2.0.0-Darwin.dmg
│   └── adsguard-ultra-2.0.0-Darwin.tar.gz
└── windows/
    ├── adsguard-ultra-2.0.0-win64.exe
    └── adsguard-ultra-2.0.0-win64.zip
```

---

## 📝 Build Configuration Options

### CMake Variables

```bash
# Build type
-DCMAKE_BUILD_TYPE=Release|Debug

# Compiler flags
-DCMAKE_CXX_FLAGS="-O3 -march=native"

# Installation prefix
-DCMAKE_INSTALL_PREFIX=/usr/local

# Enable testing
-DENABLE_TESTING=ON

# Platform-specific
-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"  # macOS universal binary
```

---

## 🔐 Security Considerations

1. **Verify Checksums:**
   ```bash
   sha256sum adsguard-ultra-2.0.0-Linux.tar.gz
   ```

2. **Code Signing (macOS):**
   ```bash
   codesign -s - adsguard_ultra
   ```

3. **Build Reproducibility:**
   ```bash
   export SOURCE_DATE_EPOCH=1672531200
   cmake -DCMAKE_BUILD_TYPE=Release ..
   ```

---

## 📞 Support

For issues or questions:
1. Check this guide's troubleshooting section
2. Review CMake output for specific errors
3. Check platform-specific requirements
4. Open an issue on GitHub

---

**Last Updated:** 2024
**Version:** 1.0.0
**Author:** MD Abu Naser Khan
**Status:** Production Ready ✅
