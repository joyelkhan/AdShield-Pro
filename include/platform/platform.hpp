#pragma once

#include <string>
#include <memory>

namespace AdShield {
namespace Platform {

/**
 * @enum PlatformType
 * @brief Supported platforms
 */
enum class PlatformType {
    WINDOWS,
    LINUX,
    MACOS,
    ANDROID,
    IOS
};

/**
 * @class PlatformInterface
 * @brief Abstract interface for platform-specific operations
 */
class PlatformInterface {
public:
    virtual ~PlatformInterface() = default;
    
    virtual PlatformType getPlatformType() const = 0;
    virtual std::string getPlatformName() const = 0;
    
    // Service/Daemon management
    virtual bool installService() = 0;
    virtual bool uninstallService() = 0;
    virtual bool startService() = 0;
    virtual bool stopService() = 0;
    
    // Network interception
    virtual bool setupNetworkInterception() = 0;
    virtual bool teardownNetworkInterception() = 0;
    
    // System integration
    virtual std::string getConfigDirectory() const = 0;
    virtual std::string getLogsDirectory() const = 0;
    virtual std::string getCacheDirectory() const = 0;
};

/**
 * @class PlatformFactory
 * @brief Factory for creating platform-specific implementations
 */
class PlatformFactory {
public:
    static std::unique_ptr<PlatformInterface> createPlatform();
    static PlatformType getCurrentPlatform();
};

} // namespace Platform
} // namespace AdShield
