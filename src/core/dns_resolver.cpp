#include "../../include/core/dns_resolver.hpp"
#include "../../include/core/logger.hpp"
#include <algorithm>
#include <cctype>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
#endif

namespace AdShield {
namespace Core {

DNSResolver::DNSResolver() {
    Logger::getInstance().info("Initializing DNS Resolver");
    loadBlockLists();
    setUpstreamDNS({
        "1.1.1.1", "1.0.0.1",           // Cloudflare
        "8.8.8.8", "8.8.4.4",           // Google
        "9.9.9.9", "149.112.112.112",   // Quad9
        "94.140.14.14", "94.140.15.15"  // AdGuard
    });
}

DNSResolver::~DNSResolver() {
    Logger::getInstance().info("DNS Resolver shutdown");
}

std::string DNSResolver::resolve(const std::string& domain) {
    {
        std::lock_guard<std::mutex> lock(dns_mutex);
        auto it = dns_cache.find(domain);
        if (it != dns_cache.end()) {
            cache_hits++;
            return it->second;
        }
    }
    
    cache_misses++;
    
    if (isBlocked(domain)) {
        blocked_count++;
        return "0.0.0.0";
    }
    
    std::string resolved_ip = performDNSLookup(domain);
    
    {
        std::lock_guard<std::mutex> lock(dns_mutex);
        dns_cache[domain] = resolved_ip;
    }
    
    return resolved_ip;
}

bool DNSResolver::isBlocked(const std::string& domain) const {
    std::string lower_domain = domain;
    std::transform(lower_domain.begin(), lower_domain.end(), lower_domain.begin(), ::tolower);
    
    std::lock_guard<std::mutex> lock(dns_mutex);
    
    // Check exact match
    if (blocked_domains.find(lower_domain) != blocked_domains.end()) {
        return true;
    }
    
    // Check subdomain match
    for (const auto& blocked : blocked_domains) {
        if (lower_domain.find(blocked) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

void DNSResolver::loadBlockLists() {
    Logger::getInstance().info("Loading blocklists");
    loadCommonBlockLists();
}

void DNSResolver::loadCommonBlockLists() {
    // Pre-populate with known ad/tracker domains
    std::vector<std::string> common_ads = {
        "doubleclick.net", "googleadservices.com", "googlesyndication.com",
        "facebook.com", "fbcdn.net", "connect.facebook.net",
        "analytics.google.com", "www.google-analytics.com",
        "adservice.google.com", "pagead2.googlesyndication.com",
        "adsystem.google.com", "securepubads.g.doubleclick.net",
        "ads.google.com", "adclick.g.doubleclick.net",
        "pagead.google.com", "partner.googleadservices.com",
        "tpc.googlesyndication.com", "www.googleadservices.com",
        "amazon-adsystem.com", "ads.amazon.com",
        "criteo.com", "criteo.net",
        "scorecardresearch.com", "beacon.scorecardresearch.com",
        "quantserve.com", "pixel.quantserve.com",
        "addthis.com", "s7.addthis.com",
        "sharethis.com", "ws.sharethis.com",
        "twitter.com", "analytics.twitter.com",
        "segment.com", "cdn.segment.com"
    };
    
    for (const auto& domain : common_ads) {
        blocked_domains.insert(domain);
    }
    
    Logger::getInstance().info("Loaded " + std::to_string(blocked_domains.size()) + " blocked domains");
}

void DNSResolver::addBlockedDomain(const std::string& domain) {
    std::lock_guard<std::mutex> lock(dns_mutex);
    blocked_domains.insert(domain);
}

void DNSResolver::removeBlockedDomain(const std::string& domain) {
    std::lock_guard<std::mutex> lock(dns_mutex);
    blocked_domains.erase(domain);
}

void DNSResolver::clearBlockList() {
    std::lock_guard<std::mutex> lock(dns_mutex);
    blocked_domains.clear();
}

void DNSResolver::setUpstreamDNS(const std::vector<std::string>& servers) {
    std::lock_guard<std::mutex> lock(dns_mutex);
    upstream_dns_servers = servers;
}

std::vector<std::string> DNSResolver::getUpstreamDNS() const {
    std::lock_guard<std::mutex> lock(dns_mutex);
    return upstream_dns_servers;
}

std::string DNSResolver::performDNSLookup(const std::string& domain) {
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(domain.c_str(), NULL, &hints, &result) == 0) {
        if (result != NULL) {
            char ip_str[INET_ADDRSTRLEN];
            struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
            inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN);
            freeaddrinfo(result);
            return std::string(ip_str);
        }
    }
    
    return "127.0.0.1";
}

} // namespace Core
} // namespace AdShield
