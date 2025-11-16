#pragma once

#ifdef __APPLE__

#include "platform.hpp"
#include <string>

namespace AdShield {
namespace Platform {

/**
 * @class MacOSPlatform
 * @brief macOS-specific implementation
 */
class MacOSPlatform : public PlatformInterface {
public:
    MacOSPlatform();
    ~MacOSPlatform() override;
    
    PlatformType getPlatformType() const override;
    std::string getPlatformName() const override;
    
    bool installService() override;
    bool uninstallService() override;
    bool startService() override;
    bool stopService() override;
    
    bool setupNetworkInterception() override;
    bool teardownNetworkInterception() override;
    
    std::string getConfigDirectory() const override;
    std::string getLogsDirectory() const override;
    std::string getCacheDirectory() const override;

private:
    static const std::string LAUNCHD_PLIST_PATH;
    static const std::string SERVICE_NAME;
};

} // namespace Platform
} // namespace AdShield

#endif // __APPLE__
