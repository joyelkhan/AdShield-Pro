find_package(Catch2 3 QUIET)

if(NOT Catch2_FOUND)
    message(STATUS "Catch2 not found, downloading...")
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        URL https://github.com/catchorg/Catch2/releases/download/v3.4.0/Catch2-3.4.0.tar.gz
    )
    FetchContent_MakeAvailable(Catch2)
endif()

# Test executable
add_executable(adshield_tests
    unit/test_config.cpp
    unit/test_logger.cpp
    unit/test_dns_resolver.cpp
    unit/test_content_filter.cpp
    unit/test_cache.cpp
    unit/test_crypto.cpp
)

target_include_directories(adshield_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(adshield_tests PRIVATE
    adshield_core
    adshield_platform
    adshield_blocklists
    Catch2::Catch2WithMain
)

# Register tests
catch_discover_tests(adshield_tests)

# Add to test target
add_test(NAME AdShieldTests COMMAND adshield_tests)
