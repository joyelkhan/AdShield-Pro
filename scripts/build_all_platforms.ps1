# ADSGUARD Ultra - Multi-Platform Build Script (PowerShell)
# Builds for Windows, macOS, and Linux with optimizations

param(
    [switch]$All,
    [switch]$SkipTests,
    [switch]$SkipAnalysis,
    [switch]$SkipPackaging,
    [string]$Configuration = "Release"
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$BuildDir = Join-Path $ProjectRoot "build"
$DistDir = Join-Path $ProjectRoot "dist"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

# ============================================================================
# DEPENDENCY CHECKING
# ============================================================================

function Test-Dependencies {
    Write-Info "Checking dependencies..."
    
    $missingDeps = @()
    
    # Check required tools
    $requiredTools = @("cmake", "git")
    
    foreach ($tool in $requiredTools) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            $missingDeps += $tool
        }
    }
    
    if ($missingDeps.Count -gt 0) {
        Write-Error "Missing dependencies: $($missingDeps -join ', ')"
        Write-Info "Please install the missing tools and try again"
        return $false
    }
    
    Write-Success "All dependencies found"
    return $true
}

# ============================================================================
# BUILD FUNCTIONS
# ============================================================================

function Build-Windows {
    Write-Info "Building for Windows..."
    
    $buildDir = Join-Path $BuildDir "windows"
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    
    Push-Location $buildDir
    
    try {
        # Check for Visual Studio
        $vsPath = & "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" `
            -latest -property installationPath 2>$null
        
        if ($vsPath) {
            Write-Info "Using Visual Studio at: $vsPath"
            cmake -G "Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=$Configuration $ProjectRoot
        } else {
            Write-Info "Using MinGW compiler"
            cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=$Configuration $ProjectRoot
        }
        
        cmake --build . --config $Configuration -j ([Environment]::ProcessorCount)
        
        # Create distribution
        $distPath = Join-Path $DistDir "windows"
        New-Item -ItemType Directory -Force -Path $distPath | Out-Null
        
        $exePath = Join-Path $buildDir "$Configuration\adsguard_ultra.exe"
        if (Test-Path $exePath) {
            Copy-Item $exePath $distPath
        }
        
        Write-Success "Windows build complete"
    }
    finally {
        Pop-Location
    }
}

function Build-Linux {
    Write-Info "Building for Linux (cross-compile)..."
    
    $buildDir = Join-Path $BuildDir "linux"
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    
    Push-Location $buildDir
    
    try {
        cmake -DCMAKE_BUILD_TYPE=$Configuration `
              -DCMAKE_CXX_FLAGS="-O3 -march=native -flto" `
              -DCMAKE_TOOLCHAIN_FILE="$ProjectRoot\cmake\linux-cross.cmake" `
              $ProjectRoot
        
        cmake --build . --config $Configuration
        
        Write-Success "Linux cross-compile complete"
    }
    finally {
        Pop-Location
    }
}

function Build-macOS {
    Write-Info "Building for macOS (cross-compile)..."
    
    $buildDir = Join-Path $BuildDir "macos"
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    
    Push-Location $buildDir
    
    try {
        cmake -DCMAKE_BUILD_TYPE=$Configuration `
              -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" `
              -DCMAKE_TOOLCHAIN_FILE="$ProjectRoot\cmake\macos-cross.cmake" `
              $ProjectRoot
        
        cmake --build . --config $Configuration
        
        Write-Success "macOS cross-compile complete"
    }
    finally {
        Pop-Location
    }
}

# ============================================================================
# TESTING
# ============================================================================

function Invoke-Tests {
    Write-Info "Running tests..."
    
    $buildDir = Join-Path $BuildDir "windows"
    
    if (-not (Test-Path $buildDir)) {
        Write-Warning "Build directory not found"
        return
    }
    
    Push-Location $buildDir
    
    try {
        ctest --output-on-failure
        Write-Success "Tests completed"
    }
    catch {
        Write-Warning "Some tests failed: $_"
    }
    finally {
        Pop-Location
    }
}

# ============================================================================
# ANALYSIS
# ============================================================================

function Invoke-Analysis {
    Write-Info "Running code analysis..."
    
    # Run Python analysis if available
    if (Get-Command python -ErrorAction SilentlyContinue) {
        & python "$ScriptDir\analyze_codebase.py" $ProjectRoot
    } else {
        Write-Warning "Python not found, skipping analysis"
    }
    
    Write-Success "Analysis completed"
}

# ============================================================================
# PACKAGING
# ============================================================================

function New-Packages {
    Write-Info "Creating distribution packages..."
    
    $buildDir = Join-Path $BuildDir "windows"
    
    if (-not (Test-Path $buildDir)) {
        Write-Warning "Build directory not found"
        return
    }
    
    Push-Location $buildDir
    
    try {
        cpack -G "ZIP;NSIS"
        Write-Success "Packages created"
    }
    catch {
        Write-Warning "CPack failed: $_"
    }
    finally {
        Pop-Location
    }
}

# ============================================================================
# MAIN ORCHESTRATION
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "🚀 ADSGUARD Ultra - Multi-Platform Build System" -ForegroundColor Magenta
    Write-Host "================================================" -ForegroundColor Magenta
    Write-Host ""
    
    # Check dependencies
    if (-not (Test-Dependencies)) {
        exit 1
    }
    
    # Create directories
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    
    # Build
    if ($All) {
        Write-Info "Building for all platforms..."
        Build-Windows
        Build-Linux
        Build-macOS
    } else {
        Write-Info "Building for Windows..."
        Build-Windows
    }
    
    # Run tests
    if (-not $SkipTests) {
        Invoke-Tests
    }
    
    # Run analysis
    if (-not $SkipAnalysis) {
        Invoke-Analysis
    }
    
    # Create packages
    if (-not $SkipPackaging) {
        New-Packages
    }
    
    Write-Host ""
    Write-Success "Build process completed successfully!"
    Write-Info "Distribution files available in: $DistDir"
    Write-Host ""
}

# ============================================================================
# ENTRY POINT
# ============================================================================

Main
