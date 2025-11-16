#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <memory>

namespace AdShield {
namespace Core {

/**
 * @class Configuration
 * @brief Centralized configuration management for AdShield Pro Ultra
 * 
 * Handles loading, saving, and runtime modification of all system settings
 * with thread-safe access patterns.
 */
class Configuration {
public:
    Configuration();
    ~Configuration() = default;

    // Configuration loading and saving
    bool loadFromFile(const std::string& filename);
    bool saveToFile(const std::string& filename);
    
    // Configuration access
    std::string get(const std::string& key, const std::string& default_value = "") const;
    void set(const std::string& key, const std::string& value);
    bool getBool(const std::string& key, bool default_value = false) const;
    void setBool(const std::string& key, bool value);
    int getInt(const std::string& key, int default_value = 0) const;
    void setInt(const std::string& key, int value);
    
    // Configuration validation
    bool validate() const;
    void reset();

private:
    mutable std::mutex config_mutex;
    std::unordered_map<std::string, std::string> settings;
    
    void initializeDefaults();
};

} // namespace Core
} // namespace AdShield
