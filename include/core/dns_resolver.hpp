#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <memory>

namespace AdShield {
namespace Core {

/**
 * @class DNSResolver
 * @brief High-performance DNS resolution with blocking capabilities
 * 
 * Provides DNS query resolution with support for:
 * - Domain blocking (ads, trackers, malware)
 * - Multiple upstream DNS servers
 * - Intelligent caching
 * - Statistics tracking
 */
class DNSResolver {
public:
    DNSResolver();
    ~DNSResolver();

    // DNS resolution
    std::string resolve(const std::string& domain);
    bool isBlocked(const std::string& domain) const;
    
    // Blocklist management
    void loadBlockLists();
    void addBlockedDomain(const std::string& domain);
    void removeBlockedDomain(const std::string& domain);
    void clearBlockList();
    
    // Upstream DNS configuration
    void setUpstreamDNS(const std::vector<std::string>& servers);
    std::vector<std::string> getUpstreamDNS() const;
    
    // Statistics
    size_t getCacheHits() const { return cache_hits.load(); }
    size_t getCacheMisses() const { return cache_misses.load(); }
    size_t getBlockedCount() const { return blocked_count.load(); }

private:
    mutable std::mutex dns_mutex;
    std::unordered_map<std::string, std::string> dns_cache;
    std::unordered_set<std::string> blocked_domains;
    std::vector<std::string> upstream_dns_servers;
    
    std::atomic<size_t> cache_hits{0};
    std::atomic<size_t> cache_misses{0};
    std::atomic<size_t> blocked_count{0};
    
    std::string performDNSLookup(const std::string& domain);
    void loadCommonBlockLists();
};

} // namespace Core
} // namespace AdShield
