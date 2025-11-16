#pragma once

#ifdef __linux__

#include "platform.hpp"
#include <string>

namespace AdShield {
namespace Platform {

/**
 * @class LinuxPlatform
 * @brief Linux-specific implementation
 */
class LinuxPlatform : public PlatformInterface {
public:
    LinuxPlatform();
    ~LinuxPlatform() override;
    
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
    static const std::string SERVICE_NAME;
    static const std::string SYSTEMD_UNIT_PATH;
};

} // namespace Platform
} // namespace AdShield

#endif // __linux__
