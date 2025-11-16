cmake_minimum_required(VERSION 3.20)
project(ADSGuard_Ultra VERSION 2.0.0 LANGUAGES CXX C)

# ============================================================================
# BUILD CONFIGURATION
# ============================================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -flto")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic")

# Platform-specific settings
if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
    add_compile_definitions(LINUX_BUILD)
elseif(APPLE)
    set(MACOS TRUE)
    add_compile_definitions(MACOS_BUILD)
elseif(WIN32)
    set(WINDOWS TRUE)
    add_compile_definitions(WINDOWS_BUILD)
endif()

# ============================================================================
# DEPENDENCIES
# ============================================================================
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(re2 REQUIRED)
find_package(Threads REQUIRED)

# Platform-specific dependencies
if(LINUX)
    find_package(liburing QUIET)
    find_package(libbpf QUIET)
endif()

# ============================================================================
# MAIN EXECUTABLE
# ============================================================================
add_executable(adsguard_ultra
    ADSGUARD.cpp
)

target_link_libraries(adsguard_ultra
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    re2::re2
    Threads::Threads
)

# Platform-specific linking
if(LINUX AND liburing_FOUND)
    target_link_libraries(adsguard_ultra PRIVATE uring)
endif()

if(LINUX AND libbpf_FOUND)
    target_link_libraries(adsguard_ultra PRIVATE bpf)
endif()

# ============================================================================
# ANALYSIS & TESTING TARGETS
# ============================================================================
enable_testing()

# Code analysis
add_custom_target(analyze
    COMMAND clang-tidy ADSGUARD.cpp --
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Running static code analysis..."
)

# Memory analysis
add_custom_target(memcheck
    COMMAND valgrind --leak-check=full --show-leak-kinds=all
            --track-origins=yes --verbose ./adsguard_ultra
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running memory analysis..."
)

# Performance profiling
add_custom_target(profile
    COMMAND perf record -g ./adsguard_ultra
    COMMAND perf report
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running performance profiling..."
)

# ============================================================================
# INSTALLATION
# ============================================================================
install(TARGETS adsguard_ultra
    RUNTIME DESTINATION bin
)

# ============================================================================
# PACKAGING
# ============================================================================
set(CPACK_PACKAGE_NAME "adsguard-ultra")
set(CPACK_PACKAGE_VERSION "2.0.0")
set(CPACK_PACKAGE_VENDOR "ADSGuard Team")
set(CPACK_PACKAGE_DESCRIPTION "Advanced DNS and Ad Filtering System")

if(WINDOWS)
    set(CPACK_GENERATOR "NSIS;ZIP")
    set(CPACK_NSIS_MODIFY_PATH ON)
elseif(MACOS)
    set(CPACK_GENERATOR "DragNDrop;ZIP")
    set(CPACK_DMG_VOLUME_NAME "ADSGuard Ultra")
elseif(LINUX)
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "ADSGuard Team")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3, libcurl4")
endif()

include(CPack)
