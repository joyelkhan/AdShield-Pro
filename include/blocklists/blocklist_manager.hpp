#pragma once

#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <memory>
#include <chrono>

namespace AdShield {
namespace BlockLists {

/**
 * @struct BlockListSource
 * @brief Represents a blocklist source
 */
struct BlockListSource {
    std::string name;
    std::string url;
    std::string format;  // "hosts", "adblock", "dnsmasq", etc.
    bool enabled;
    std::chrono::hours update_interval;
    std::chrono::system_clock::time_point last_updated;
};

/**
 * @class BlockListManager
 * @brief Manages blocklist sources and updates
 * 
 * Integrates blocklists from:
 * - AdAway
 * - AdGuard
 * - StevenBlack
 * - Malware domain lists
 * - Custom user lists
 */
class BlockListManager {
public:
    BlockListManager();
    ~BlockListManager();
    
    // Blocklist source management
    void addSource(const BlockListSource& source);
    void removeSource(const std::string& name);
    void enableSource(const std::string& name, bool enable);
    std::vector<BlockListSource> getSources() const;
    
    // Blocklist updates
    bool updateAllBlockLists();
    bool updateBlockList(const std::string& name);
    
    // Blocklist access
    const std::unordered_set<std::string>& getBlockedDomains() const;
    size_t getBlockedDomainCount() const;
    
    // Statistics
    struct BlockListStats {
        size_t total_domains;
        size_t active_sources;
        std::chrono::system_clock::time_point last_update;
        std::vector<std::pair<std::string, size_t>> source_counts;
    };
    
    BlockListStats getStatistics() const;

private:
    mutable std::mutex manager_mutex;
    std::vector<BlockListSource> sources;
    std::unordered_set<std::string> blocked_domains;
    
    void initializeDefaultSources();
    bool downloadAndParseBlockList(const BlockListSource& source);
    void parseHostsFormat(const std::string& content);
    void parseAdBlockFormat(const std::string& content);
    void parseDnsMasqFormat(const std::string& content);
};

} // namespace BlockLists
} // namespace AdShield
