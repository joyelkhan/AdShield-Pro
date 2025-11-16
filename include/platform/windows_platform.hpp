#pragma once

#ifdef _WIN32

#include "platform.hpp"
#include <string>

namespace AdShield {
namespace Platform {

/**
 * @class WindowsPlatform
 * @brief Windows-specific implementation
 */
class WindowsPlatform : public PlatformInterface {
public:
    WindowsPlatform();
    ~WindowsPlatform() override;
    
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
    static const std::string SERVICE_DISPLAY_NAME;
};

} // namespace Platform
} // namespace AdShield

#endif // _WIN32
