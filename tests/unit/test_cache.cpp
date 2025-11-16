#include <catch2/catch_test_macros.hpp>
#include "../../include/core/cache.hpp"

using namespace AdShield::Core;

TEST_CASE("Cache - Put and Get", "[cache]") {
    Cache<std::string, std::string> cache(100);
    
    cache.put("key1", "value1");
    
    std::string value;
    REQUIRE(cache.get("key1", value) == true);
    REQUIRE(value == "value1");
}

TEST_CASE("Cache - Get Non-Existent Key", "[cache]") {
    Cache<std::string, std::string> cache(100);
    
    std::string value;
    REQUIRE(cache.get("nonexistent", value) == false);
}

TEST_CASE("Cache - Update Existing Key", "[cache]") {
    Cache<std::string, std::string> cache(100);
    
    cache.put("key1", "value1");
    cache.put("key1", "value2");
    
    std::string value;
    cache.get("key1", value);
    REQUIRE(value == "value2");
}

TEST_CASE("Cache - Capacity Limit", "[cache]") {
    Cache<std::string, std::string> cache(2);
    
    cache.put("key1", "value1");
    cache.put("key2", "value2");
    cache.put("key3", "value3");  // Should evict key1
    
    std::string value;
    REQUIRE(cache.get("key1", value) == false);  // key1 should be evicted
    REQUIRE(cache.get("key2", value) == true);
    REQUIRE(cache.get("key3", value) == true);
}

TEST_CASE("Cache - Clear", "[cache]") {
    Cache<std::string, std::string> cache(100);
    
    cache.put("key1", "value1");
    cache.put("key2", "value2");
    cache.clear();
    
    std::string value;
    REQUIRE(cache.get("key1", value) == false);
    REQUIRE(cache.get("key2", value) == false);
    REQUIRE(cache.getSize() == 0);
}

TEST_CASE("Cache - Size Tracking", "[cache]") {
    Cache<std::string, std::string> cache(100);
    
    REQUIRE(cache.getSize() == 0);
    
    cache.put("key1", "value1");
    REQUIRE(cache.getSize() == 1);
    
    cache.put("key2", "value2");
    REQUIRE(cache.getSize() == 2);
}
