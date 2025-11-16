#include <catch2/catch_test_macros.hpp>
#include "../../include/core/config.hpp"

using namespace AdShield::Core;

TEST_CASE("Configuration - Default Values", "[config]") {
    Configuration config;
    
    REQUIRE(config.get("dns_blocking_enabled") == "true");
    REQUIRE(config.get("cache_size") == "100000");
    REQUIRE(config.get("dns_timeout") == "3000");
}

TEST_CASE("Configuration - Get/Set String", "[config]") {
    Configuration config;
    
    config.set("test_key", "test_value");
    REQUIRE(config.get("test_key") == "test_value");
}

TEST_CASE("Configuration - Get/Set Boolean", "[config]") {
    Configuration config;
    
    config.setBool("test_bool", true);
    REQUIRE(config.getBool("test_bool") == true);
    
    config.setBool("test_bool", false);
    REQUIRE(config.getBool("test_bool") == false);
}

TEST_CASE("Configuration - Get/Set Integer", "[config]") {
    Configuration config;
    
    config.setInt("test_int", 42);
    REQUIRE(config.getInt("test_int") == 42);
}

TEST_CASE("Configuration - Default Values for Missing Keys", "[config]") {
    Configuration config;
    
    REQUIRE(config.get("nonexistent", "default") == "default");
    REQUIRE(config.getBool("nonexistent", true) == true);
    REQUIRE(config.getInt("nonexistent", 99) == 99);
}

TEST_CASE("Configuration - Validation", "[config]") {
    Configuration config;
    REQUIRE(config.validate() == true);
}

TEST_CASE("Configuration - Reset", "[config]") {
    Configuration config;
    config.set("custom_key", "custom_value");
    
    config.reset();
    
    REQUIRE(config.get("custom_key") == "");
    REQUIRE(config.get("dns_blocking_enabled") == "true");
}
