cmake_minimum_required(VERSION 3.16)
project(AdShieldProUltra VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

# Platform-specific settings
if(WIN32)
    set(PLATFORM_SOURCES
        src/platform/windows_platform.cpp
    )
    set(PLATFORM_LIBS ws2_32 iphlpapi)
elseif(UNIX AND NOT APPLE)
    set(PLATFORM_SOURCES
        src/platform/linux_platform.cpp
    )
    set(PLATFORM_LIBS)
elseif(APPLE)
    set(PLATFORM_SOURCES
        src/platform/macos_platform.cpp
    )
    set(PLATFORM_LIBS)
endif()

# Core library sources
set(CORE_SOURCES
    src/core/config.cpp
    src/core/logger.cpp
    src/core/dns_resolver.cpp
    src/core/content_filter.cpp
    src/core/crypto.cpp
    src/core/controller.cpp
)

# Platform library sources
set(PLATFORM_LIB_SOURCES
    src/platform/platform.cpp
    ${PLATFORM_SOURCES}
)

# Blocklist library sources
set(BLOCKLIST_SOURCES
    src/blocklists/blocklist_manager.cpp
)

# Create core library
add_library(adshield_core STATIC ${CORE_SOURCES})
target_include_directories(adshield_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(adshield_core PUBLIC OpenSSL::SSL OpenSSL::Crypto CURL::libcurl Threads::Threads)

# Create platform library
add_library(adshield_platform STATIC ${PLATFORM_LIB_SOURCES})
target_include_directories(adshield_platform PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(adshield_platform PUBLIC adshield_core ${PLATFORM_LIBS})

# Create blocklist library
add_library(adshield_blocklists STATIC ${BLOCKLIST_SOURCES})
target_include_directories(adshield_blocklists PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(adshield_blocklists PUBLIC adshield_core)

# Create main executable
add_executable(adshield_pro src/main/main.cpp)
target_include_directories(adshield_pro PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(adshield_pro PRIVATE adshield_core adshield_platform adshield_blocklists)

# Compiler flags
if(MSVC)
    target_compile_options(adshield_pro PRIVATE /W4 /WX)
    target_compile_options(adshield_core PRIVATE /W4 /WX)
    target_compile_options(adshield_platform PRIVATE /W4 /WX)
    target_compile_options(adshield_blocklists PRIVATE /W4 /WX)
else()
    target_compile_options(adshield_pro PRIVATE -Wall -Wextra -Werror -O3)
    target_compile_options(adshield_core PRIVATE -Wall -Wextra -Werror -O3)
    target_compile_options(adshield_platform PRIVATE -Wall -Wextra -Werror -O3)
    target_compile_options(adshield_blocklists PRIVATE -Wall -Wextra -Werror -O3)
endif()

# Installation
install(TARGETS adshield_pro DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)
install(DIRECTORY resources/ DESTINATION share/adshield-pro)

# Testing
enable_testing()
add_subdirectory(tests)
