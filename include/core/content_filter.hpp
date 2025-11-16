#pragma once

#include <string>
#include <vector>
#include <regex>
#include <unordered_set>
#include <mutex>
#include <memory>

namespace AdShield {
namespace Core {

/**
 * @class ContentFilter
 * @brief Advanced content filtering engine for HTTP/HTTPS traffic
 * 
 * Provides filtering capabilities for:
 * - Ad blocking (patterns and domain-based)
 * - Tracker blocking
 * - Malware protection
 * - Custom user rules
 * - HTML content sanitization
 */
class ContentFilter {
public:
    ContentFilter();
    ~ContentFilter();

    // Content filtering decisions
    bool shouldBlock(const std::string& url, const std::string& host) const;
    std::string filterHTML(const std::string& html, const std::string& url);
    
    // Custom rule management
    void addCustomRule(const std::string& pattern);
    void removeCustomRule(const std::string& pattern);
    void clearCustomRules();
    
    // Filter configuration
    void enableAdBlocking(bool enable);
    void enableTrackerBlocking(bool enable);
    void enableMalwareBlocking(bool enable);
    
    // Statistics
    size_t getBlockedCount() const { return blocked_count; }

private:
    mutable std::mutex filter_mutex;
    std::vector<std::regex> ad_patterns;
    std::vector<std::regex> tracker_patterns;
    std::vector<std::regex> malware_patterns;
    std::vector<std::regex> custom_patterns;
    std::unordered_set<std::string> blocked_urls;
    
    std::atomic<size_t> blocked_count{0};
    
    bool ad_blocking_enabled{true};
    bool tracker_blocking_enabled{true};
    bool malware_blocking_enabled{true};
    
    void initializePatterns();
    bool matchesPattern(const std::string& text, const std::vector<std::regex>& patterns) const;
};

} // namespace Core
} // namespace AdShield
