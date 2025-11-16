#include <catch2/catch_test_macros.hpp>
#include "../../include/core/dns_resolver.hpp"

using namespace AdShield::Core;

TEST_CASE("DNS Resolver - Initialization", "[dns]") {
    DNSResolver resolver;
    
    REQUIRE(resolver.getUpstreamDNS().size() > 0);
}

TEST_CASE("DNS Resolver - Domain Blocking", "[dns]") {
    DNSResolver resolver;
    
    REQUIRE(resolver.isBlocked("doubleclick.net") == true);
    REQUIRE(resolver.isBlocked("googleadservices.com") == true);
}

TEST_CASE("DNS Resolver - Add/Remove Blocked Domain", "[dns]") {
    DNSResolver resolver;
    
    resolver.addBlockedDomain("test.example.com");
    REQUIRE(resolver.isBlocked("test.example.com") == true);
    
    resolver.removeBlockedDomain("test.example.com");
    REQUIRE(resolver.isBlocked("test.example.com") == false);
}

TEST_CASE("DNS Resolver - Cache Statistics", "[dns]") {
    DNSResolver resolver;
    
    REQUIRE(resolver.getCacheHits() >= 0);
    REQUIRE(resolver.getCacheMisses() >= 0);
    REQUIRE(resolver.getBlockedCount() >= 0);
}

TEST_CASE("DNS Resolver - Upstream DNS Configuration", "[dns]") {
    DNSResolver resolver;
    
    std::vector<std::string> custom_dns = {"8.8.8.8", "8.8.4.4"};
    resolver.setUpstreamDNS(custom_dns);
    
    auto dns_servers = resolver.getUpstreamDNS();
    REQUIRE(dns_servers.size() == 2);
    REQUIRE(dns_servers[0] == "8.8.8.8");
}

TEST_CASE("DNS Resolver - Clear Blocklist", "[dns]") {
    DNSResolver resolver;
    
    resolver.clearBlockList();
    REQUIRE(resolver.isBlocked("doubleclick.net") == false);
}
