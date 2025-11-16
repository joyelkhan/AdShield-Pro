#include <catch2/catch_test_macros.hpp>
#include "../../include/core/content_filter.hpp"

using namespace AdShield::Core;

TEST_CASE("Content Filter - Initialization", "[filter]") {
    ContentFilter filter;
    
    REQUIRE_NOTHROW(filter.shouldBlock("http://example.com", "example.com"));
}

TEST_CASE("Content Filter - Ad Blocking", "[filter]") {
    ContentFilter filter;
    
    REQUIRE(filter.shouldBlock("http://ads.example.com/banner.js", "example.com") == true);
    REQUIRE(filter.shouldBlock("http://example.com/adserver/ad.js", "example.com") == true);
}

TEST_CASE("Content Filter - Tracker Blocking", "[filter]") {
    ContentFilter filter;
    
    REQUIRE(filter.shouldBlock("http://example.com/track", "example.com") == true);
    REQUIRE(filter.shouldBlock("http://example.com/analytics", "example.com") == true);
}

TEST_CASE("Content Filter - Custom Rules", "[filter]") {
    ContentFilter filter;
    
    filter.addCustomRule(R"(/custom-pattern/)");
    REQUIRE(filter.shouldBlock("http://example.com/custom-pattern/file.js", "example.com") == true);
}

TEST_CASE("Content Filter - Enable/Disable Features", "[filter]") {
    ContentFilter filter;
    
    filter.enableAdBlocking(false);
    REQUIRE(filter.shouldBlock("http://ads.example.com/banner.js", "example.com") == false);
    
    filter.enableAdBlocking(true);
    REQUIRE(filter.shouldBlock("http://ads.example.com/banner.js", "example.com") == true);
}

TEST_CASE("Content Filter - HTML Filtering", "[filter]") {
    ContentFilter filter;
    
    std::string html = "<script>ads.js</script><div class='ads'>Ad content</div>";
    std::string filtered = filter.filterHTML(html, "http://example.com");
    
    REQUIRE(filtered.find("<script>") == std::string::npos);
}

TEST_CASE("Content Filter - Clear Custom Rules", "[filter]") {
    ContentFilter filter;
    
    filter.addCustomRule(R"(/test/)");
    filter.clearCustomRules();
    
    REQUIRE(filter.shouldBlock("http://example.com/test/file.js", "example.com") == false);
}
