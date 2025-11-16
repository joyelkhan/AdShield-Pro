@echo off
REM AdShield Pro Ultra - Build Script for Windows
REM Usage: build.bat [debug|release]

setlocal enabledelayedexpansion

set BUILD_TYPE=%1
if "%BUILD_TYPE%"=="" set BUILD_TYPE=release

set BUILD_DIR=build
set GENERATOR=Visual Studio 16 2019

echo ================================
echo AdShield Pro Ultra Build Script
echo ================================
echo Build Type: %BUILD_TYPE%
echo Build Directory: %BUILD_DIR%
echo.

REM Check for CMake
where cmake >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake not found. Please install CMake 3.16 or higher.
    exit /b 1
)

REM Check for Visual Studio
where cl.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Visual Studio compiler not found.
    exit /b 1
)

echo Checking for required tools... OK
echo.

REM Create build directory
if not exist "%BUILD_DIR%" (
    echo Creating build directory...
    mkdir "%BUILD_DIR%"
)

REM Configure
echo Configuring CMake...
cd "%BUILD_DIR%"
cmake -G "%GENERATOR%" ^
       -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
       ..

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configuration failed.
    exit /b 1
)

REM Build
echo Building AdShield Pro Ultra...
cmake --build . --config %BUILD_TYPE% --parallel

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed.
    exit /b 1
)

echo.
echo Build completed successfully!
echo.
echo To install, run: cmake --install .
echo To run tests, run: ctest --output-on-failure
