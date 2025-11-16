#include "../../include/core/config.hpp"
#include "../../include/core/logger.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace AdShield {
namespace Core {

Configuration::Configuration() {
    initializeDefaults();
}

void Configuration::initializeDefaults() {
    settings = {
        {"dns_blocking_enabled", "true"},
        {"https_filtering_enabled", "true"},
        {"stealth_mode", "true"},
        {"aggressive_blocking", "true"},
        {"log_level", "1"},
        {"max_connections", "1000"},
        {"dns_timeout", "3000"},
        {"cache_size", "100000"},
        {"update_frequency", "3600"},
        {"compression_level", "9"},
        {"encryption_enabled", "true"},
        {"bypass_local", "false"},
        {"block_trackers", "true"},
        {"block_malware", "true"},
        {"block_phishing", "true"},
        {"parental_control", "false"},
        {"custom_rules_enabled", "true"},
        {"performance_mode", "true"},
        {"memory_optimization", "true"},
        {"enable_statistics", "true"},
        {"statistics_interval", "60"}
    };
}

bool Configuration::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        Logger::getInstance().warning("Configuration file not found: " + filename);
        return false;
    }

    std::lock_guard<std::mutex> lock(config_mutex);
    std::string line;
    int line_count = 0;
    
    while (std::getline(file, line)) {
        line_count++;
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;
        
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            // Trim whitespace
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            
            settings[key] = value;
        }
    }
    
    Logger::getInstance().info("Loaded " + std::to_string(line_count) + " configuration entries");
    return true;
}

bool Configuration::saveToFile(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        Logger::getInstance().error("Failed to open configuration file for writing: " + filename);
        return false;
    }

    std::lock_guard<std::mutex> lock(config_mutex);
    
    file << "# AdShield Pro Ultra Configuration\n";
    file << "# Generated automatically\n\n";
    
    for (const auto& [key, value] : settings) {
        file << key << "=" << value << "\n";
    }
    
    Logger::getInstance().info("Configuration saved to: " + filename);
    return true;
}

std::string Configuration::get(const std::string& key, const std::string& default_value) const {
    std::lock_guard<std::mutex> lock(config_mutex);
    auto it = settings.find(key);
    return it != settings.end() ? it->second : default_value;
}

void Configuration::set(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(config_mutex);
    settings[key] = value;
}

bool Configuration::getBool(const std::string& key, bool default_value) const {
    std::string value = get(key);
    if (value.empty()) return default_value;
    
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    return value == "true" || value == "1" || value == "yes";
}

void Configuration::setBool(const std::string& key, bool value) {
    set(key, value ? "true" : "false");
}

int Configuration::getInt(const std::string& key, int default_value) const {
    std::string value = get(key);
    if (value.empty()) return default_value;
    
    try {
        return std::stoi(value);
    } catch (...) {
        return default_value;
    }
}

void Configuration::setInt(const std::string& key, int value) {
    set(key, std::to_string(value));
}

bool Configuration::validate() const {
    std::lock_guard<std::mutex> lock(config_mutex);
    
    // Validate critical settings
    if (settings.find("dns_timeout") == settings.end()) return false;
    if (settings.find("cache_size") == settings.end()) return false;
    
    return true;
}

void Configuration::reset() {
    std::lock_guard<std::mutex> lock(config_mutex);
    settings.clear();
    initializeDefaults();
    Logger::getInstance().info("Configuration reset to defaults");
}

} // namespace Core
} // namespace AdShield
