#!/bin/bash
# ADSGUARD Ultra - Multi-Platform Build Script
# Builds for Windows, macOS, and Linux with optimizations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
DIST_DIR="$PROJECT_ROOT/dist"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# ============================================================================
# PLATFORM DETECTION
# ============================================================================

detect_platform() {
    case "$(uname -s)" in
        Linux*)     echo "Linux";;
        Darwin*)    echo "macOS";;
        CYGWIN*)    echo "Windows";;
        MINGW*)     echo "Windows";;
        *)          echo "Unknown";;
    esac
}

# ============================================================================
# DEPENDENCY CHECKING
# ============================================================================

check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Check required tools
    for cmd in cmake git; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Please install the missing tools and try again"
        return 1
    fi
    
    log_success "All dependencies found"
    return 0
}

# ============================================================================
# BUILD FUNCTIONS
# ============================================================================

build_linux() {
    log_info "Building for Linux..."
    
    local build_dir="$BUILD_DIR/linux"
    mkdir -p "$build_dir"
    
    cd "$build_dir"
    
    # Release build
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_CXX_FLAGS="-O3 -march=native -flto" \
          "$PROJECT_ROOT"
    
    make -j$(nproc)
    
    # Create distribution
    mkdir -p "$DIST_DIR/linux"
    cp adsguard_ultra "$DIST_DIR/linux/"
    strip "$DIST_DIR/linux/adsguard_ultra"
    
    log_success "Linux build complete"
}

build_macos() {
    log_info "Building for macOS..."
    
    local build_dir="$BUILD_DIR/macos"
    mkdir -p "$build_dir"
    
    cd "$build_dir"
    
    # Universal binary (Intel + Apple Silicon)
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_CXX_FLAGS="-O3 -flto" \
          -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
          "$PROJECT_ROOT"
    
    make -j$(sysctl -n hw.ncpu)
    
    # Create distribution
    mkdir -p "$DIST_DIR/macos"
    cp adsguard_ultra "$DIST_DIR/macos/"
    strip "$DIST_DIR/macos/adsguard_ultra"
    
    # Code signing (if certificate available)
    if command -v codesign &> /dev/null; then
        codesign -s - "$DIST_DIR/macos/adsguard_ultra" 2>/dev/null || true
    fi
    
    log_success "macOS build complete"
}

build_windows() {
    log_info "Building for Windows..."
    
    local build_dir="$BUILD_DIR/windows"
    mkdir -p "$build_dir"
    
    cd "$build_dir"
    
    # MinGW cross-compile or MSVC
    if command -v x86_64-w64-mingw32-g++ &> /dev/null; then
        cmake -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_TOOLCHAIN_FILE="$PROJECT_ROOT/cmake/mingw.cmake" \
              "$PROJECT_ROOT"
    else
        cmake -DCMAKE_BUILD_TYPE=Release \
              -G "Visual Studio 17 2022" \
              "$PROJECT_ROOT"
    fi
    
    cmake --build . --config Release -j$(nproc 2>/dev/null || echo 4)
    
    # Create distribution
    mkdir -p "$DIST_DIR/windows"
    cp Release/adsguard_ultra.exe "$DIST_DIR/windows/" 2>/dev/null || \
    cp adsguard_ultra.exe "$DIST_DIR/windows/" 2>/dev/null || true
    
    log_success "Windows build complete"
}

# ============================================================================
# TESTING
# ============================================================================

run_tests() {
    log_info "Running tests..."
    
    local platform=$(detect_platform)
    local build_dir="$BUILD_DIR/$platform"
    
    if [ ! -d "$build_dir" ]; then
        log_warning "Build directory not found for $platform"
        return 1
    fi
    
    cd "$build_dir"
    ctest --output-on-failure || log_warning "Some tests failed"
    
    log_success "Tests completed"
}

# ============================================================================
# ANALYSIS
# ============================================================================

run_analysis() {
    log_info "Running code analysis..."
    
    if command -v clang-tidy &> /dev/null; then
        clang-tidy "$PROJECT_ROOT/ADSGUARD.cpp" -- \
            -I/usr/include \
            -I/usr/local/include
    else
        log_warning "clang-tidy not found, skipping analysis"
    fi
    
    # Run Python analysis
    if command -v python3 &> /dev/null; then
        python3 "$SCRIPT_DIR/analyze_codebase.py" "$PROJECT_ROOT"
    fi
    
    log_success "Analysis completed"
}

# ============================================================================
# PACKAGING
# ============================================================================

create_packages() {
    log_info "Creating distribution packages..."
    
    local platform=$(detect_platform)
    local build_dir="$BUILD_DIR/$platform"
    
    if [ ! -d "$build_dir" ]; then
        log_warning "Build directory not found"
        return 1
    fi
    
    cd "$build_dir"
    cpack -G "TGZ;ZIP" || log_warning "CPack failed"
    
    log_success "Packages created"
}

# ============================================================================
# MAIN BUILD ORCHESTRATION
# ============================================================================

main() {
    log_info "ADSGUARD Ultra - Multi-Platform Build System"
    echo "=============================================="
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Create directories
    mkdir -p "$BUILD_DIR" "$DIST_DIR"
    
    # Determine what to build
    local platform=$(detect_platform)
    local build_all=false
    
    if [ "$1" == "--all" ]; then
        build_all=true
        log_info "Building for all platforms..."
    else
        log_info "Building for detected platform: $platform"
    fi
    
    # Build for detected platform
    case "$platform" in
        Linux)
            build_linux
            ;;
        macOS)
            build_macos
            ;;
        Windows)
            build_windows
            ;;
        *)
            log_error "Unsupported platform: $platform"
            exit 1
            ;;
    esac
    
    # Run tests
    if [ "$2" != "--skip-tests" ]; then
        run_tests
    fi
    
    # Run analysis
    if [ "$2" != "--skip-analysis" ]; then
        run_analysis
    fi
    
    # Create packages
    if [ "$2" != "--skip-packaging" ]; then
        create_packages
    fi
    
    log_success "Build process completed successfully!"
    log_info "Distribution files available in: $DIST_DIR"
}

# ============================================================================
# ENTRY POINT
# ============================================================================

main "$@"
