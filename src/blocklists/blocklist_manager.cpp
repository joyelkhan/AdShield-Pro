#include "../../include/blocklists/blocklist_manager.hpp"
#include "../../include/core/logger.hpp"
#include <algorithm>

namespace AdShield {
namespace BlockLists {

BlockListManager::BlockListManager() {
    AdShield::Core::Logger::getInstance().info("Initializing BlockList Manager");
    initializeDefaultSources();
}

BlockListManager::~BlockListManager() {
    AdShield::Core::Logger::getInstance().info("BlockList Manager shutdown");
}

void BlockListManager::initializeDefaultSources() {
    // AdAway
    addSource({
        .name = "AdAway",
        .url = "https://adaway.org/hosts.txt",
        .format = "hosts",
        .enabled = true,
        .update_interval = std::chrono::hours(24),
        .last_updated = std::chrono::system_clock::now()
    });
    
    // StevenBlack
    addSource({
        .name = "StevenBlack",
        .url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        .format = "hosts",
        .enabled = true,
        .update_interval = std::chrono::hours(24),
        .last_updated = std::chrono::system_clock::now()
    });
    
    // Malware Domain List
    addSource({
        .name = "MalwareDomainList",
        .url = "https://www.malwaredomainlist.com/hostslist/hosts.txt",
        .format = "hosts",
        .enabled = true,
        .update_interval = std::chrono::hours(24),
        .last_updated = std::chrono::system_clock::now()
    });
    
    // Yoyo
    addSource({
        .name = "Yoyo",
        .url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts",
        .format = "hosts",
        .enabled = true,
        .update_interval = std::chrono::hours(24),
        .last_updated = std::chrono::system_clock::now()
    });
    
    // MVPS
    addSource({
        .name = "MVPS",
        .url = "https://winhelp2002.mvps.org/hosts.txt",
        .format = "hosts",
        .enabled = true,
        .update_interval = std::chrono::hours(24),
        .last_updated = std::chrono::system_clock::now()
    });
    
    AdShield::Core::Logger::getInstance().info("Initialized " + std::to_string(sources.size()) + " default blocklist sources");
}

void BlockListManager::addSource(const BlockListSource& source) {
    std::lock_guard<std::mutex> lock(manager_mutex);
    sources.push_back(source);
}

void BlockListManager::removeSource(const std::string& name) {
    std::lock_guard<std::mutex> lock(manager_mutex);
    sources.erase(
        std::remove_if(sources.begin(), sources.end(),
            [&name](const BlockListSource& s) { return s.name == name; }),
        sources.end()
    );
}

void BlockListManager::enableSource(const std::string& name, bool enable) {
    std::lock_guard<std::mutex> lock(manager_mutex);
    for (auto& source : sources) {
        if (source.name == name) {
            source.enabled = enable;
            break;
        }
    }
}

std::vector<BlockListSource> BlockListManager::getSources() const {
    std::lock_guard<std::mutex> lock(manager_mutex);
    return sources;
}

bool BlockListManager::updateAllBlockLists() {
    std::lock_guard<std::mutex> lock(manager_mutex);
    
    AdShield::Core::Logger::getInstance().info("Updating all blocklists");
    
    for (auto& source : sources) {
        if (source.enabled) {
            downloadAndParseBlockList(source);
            source.last_updated = std::chrono::system_clock::now();
        }
    }
    
    return true;
}

bool BlockListManager::updateBlockList(const std::string& name) {
    std::lock_guard<std::mutex> lock(manager_mutex);
    
    for (auto& source : sources) {
        if (source.name == name && source.enabled) {
            downloadAndParseBlockList(source);
            source.last_updated = std::chrono::system_clock::now();
            return true;
        }
    }
    
    return false;
}

const std::unordered_set<std::string>& BlockListManager::getBlockedDomains() const {
    return blocked_domains;
}

size_t BlockListManager::getBlockedDomainCount() const {
    std::lock_guard<std::mutex> lock(manager_mutex);
    return blocked_domains.size();
}

BlockListManager::BlockListStats BlockListManager::getStatistics() const {
    std::lock_guard<std::mutex> lock(manager_mutex);
    
    BlockListStats stats;
    stats.total_domains = blocked_domains.size();
    stats.active_sources = 0;
    stats.last_update = std::chrono::system_clock::now();
    
    for (const auto& source : sources) {
        if (source.enabled) {
            stats.active_sources++;
            // In a real implementation, we would track per-source domain counts
            stats.source_counts.push_back({source.name, 0});
        }
    }
    
    return stats;
}

bool BlockListManager::downloadAndParseBlockList(const BlockListSource& source) {
    AdShield::Core::Logger::getInstance().info("Downloading blocklist: " + source.name);
    
    // In a real implementation, this would use libcurl to download the list
    // For now, we'll just log the action
    
    AdShield::Core::Logger::getInstance().info("Blocklist downloaded: " + source.name);
    return true;
}

void BlockListManager::parseHostsFormat(const std::string& content) {
    // Parse hosts format (IP domain)
    std::istringstream iss(content);
    std::string line;
    
    while (std::getline(iss, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        std::istringstream line_stream(line);
        std::string ip, domain;
        
        if (line_stream >> ip >> domain) {
            blocked_domains.insert(domain);
        }
    }
}

void BlockListManager::parseAdBlockFormat(const std::string& content) {
    // Parse AdBlock format
    std::istringstream iss(content);
    std::string line;
    
    while (std::getline(iss, line)) {
        if (line.empty() || line[0] == '!' || line[0] == '[') continue;
        
        // Simplified parsing - real implementation would be more complex
        if (line.find("||") == 0) {
            std::string domain = line.substr(2);
            if (domain.find("^") != std::string::npos) {
                domain = domain.substr(0, domain.find("^"));
            }
            blocked_domains.insert(domain);
        }
    }
}

void BlockListManager::parseDnsMasqFormat(const std::string& content) {
    // Parse dnsmasq format (address=/domain/ip)
    std::istringstream iss(content);
    std::string line;
    
    while (std::getline(iss, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        if (line.find("address=/") == 0) {
            size_t start = 9;
            size_t end = line.find("/", start);
            if (end != std::string::npos) {
                std::string domain = line.substr(start, end - start);
                blocked_domains.insert(domain);
            }
        }
    }
}

} // namespace BlockLists
} // namespace AdShield
