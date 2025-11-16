#pragma once

#include <memory>
#include <atomic>
#include <thread>
#include <vector>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>

#include "config.hpp"
#include "dns_resolver.hpp"
#include "content_filter.hpp"
#include "crypto.hpp"
#include "cache.hpp"
#include "logger.hpp"

namespace AdShield {
namespace Core {

/**
 * @class AdShieldController
 * @brief Main controller orchestrating all AdShield components
 * 
 * Coordinates:
 * - DNS resolution and blocking
 * - Content filtering
 * - Network interception
 * - Caching and performance optimization
 * - Statistics and monitoring
 */
class AdShieldController {
public:
    AdShieldController();
    ~AdShieldController();
    
    // Lifecycle management
    bool initialize();
    void shutdown();
    bool isRunning() const { return running.load(); }
    
    // Configuration
    Configuration& getConfig() { return config; }
    const Configuration& getConfig() const { return config; }
    
    // DNS operations
    std::string resolveDomain(const std::string& domain);
    bool isDomainBlocked(const std::string& domain) const;
    
    // Content filtering
    bool shouldBlockContent(const std::string& url, const std::string& host) const;
    std::string filterContent(const std::string& content, const std::string& url);
    
    // Blocklist management
    void updateBlockLists();
    void addCustomRule(const std::string& rule);
    
    // Statistics
    struct Statistics {
        size_t dns_queries_blocked;
        size_t http_requests_filtered;
        size_t cache_hits;
        size_t cache_misses;
        double cache_hit_rate;
        size_t memory_usage;
        std::chrono::seconds uptime;
    };
    
    Statistics getStatistics() const;
    void resetStatistics();

private:
    std::atomic<bool> running{false};
    
    // Core components
    Configuration config;
    DNSResolver dns_resolver;
    ContentFilter content_filter;
    CryptoEngine crypto;
    Cache<std::string, std::string> response_cache;
    
    // Worker thread pool
    std::vector<std::thread> worker_threads;
    std::queue<std::function<void()>> task_queue;
    mutable std::mutex queue_mutex;
    std::condition_variable queue_cv;
    
    // Statistics
    std::atomic<size_t> dns_queries_blocked{0};
    std::atomic<size_t> http_requests_filtered{0};
    std::chrono::steady_clock::time_point start_time;
    
    // Internal methods
    void startWorkerThreads();
    void stopWorkerThreads();
    void workerLoop();
    void downloadBlockList(const std::string& url);
};

} // namespace Core
} // namespace AdShield
