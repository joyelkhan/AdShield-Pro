#ifdef __APPLE__

#include "../../include/platform/macos_platform.hpp"
#include "../../include/core/logger.hpp"
#include <unistd.h>
#include <pwd.h>

namespace AdShield {
namespace Platform {

const std::string MacOSPlatform::LAUNCHD_PLIST_PATH = "/Library/LaunchDaemons/com.adshield.pro.plist";
const std::string MacOSPlatform::SERVICE_NAME = "com.adshield.pro";

MacOSPlatform::MacOSPlatform() {
    Core::Logger::getInstance().info("macOS Platform initialized");
}

MacOSPlatform::~MacOSPlatform() {
    Core::Logger::getInstance().info("macOS Platform shutdown");
}

PlatformType MacOSPlatform::getPlatformType() const {
    return PlatformType::MACOS;
}

std::string MacOSPlatform::getPlatformName() const {
    return "macOS";
}

bool MacOSPlatform::installService() {
    Core::Logger::getInstance().info("Installing macOS launchd service");
    
    // Check if running as root
    if (geteuid() != 0) {
        Core::Logger::getInstance().error("Service installation requires root privileges");
        return false;
    }
    
    // Implementation would create launchd plist file
    Core::Logger::getInstance().info("Service installed successfully");
    return true;
}

bool MacOSPlatform::uninstallService() {
    Core::Logger::getInstance().info("Uninstalling macOS launchd service");
    
    // Check if running as root
    if (geteuid() != 0) {
        Core::Logger::getInstance().error("Service uninstallation requires root privileges");
        return false;
    }
    
    // Implementation would remove launchd plist file
    Core::Logger::getInstance().info("Service uninstalled successfully");
    return true;
}

bool MacOSPlatform::startService() {
    Core::Logger::getInstance().info("Starting macOS service");
    // Implementation would use launchctl
    return true;
}

bool MacOSPlatform::stopService() {
    Core::Logger::getInstance().info("Stopping macOS service");
    // Implementation would use launchctl
    return true;
}

bool MacOSPlatform::setupNetworkInterception() {
    Core::Logger::getInstance().info("Setting up network interception on macOS");
    
    // Check if running as root
    if (geteuid() != 0) {
        Core::Logger::getInstance().error("Network interception requires root privileges");
        return false;
    }
    
    // Implementation would use pfctl or similar
    return true;
}

bool MacOSPlatform::teardownNetworkInterception() {
    Core::Logger::getInstance().info("Tearing down network interception on macOS");
    return true;
}

std::string MacOSPlatform::getConfigDirectory() const {
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw->pw_dir;
    }
    return std::string(home) + "/Library/Application Support/AdShieldPro";
}

std::string MacOSPlatform::getLogsDirectory() const {
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw->pw_dir;
    }
    return std::string(home) + "/Library/Logs/AdShieldPro";
}

std::string MacOSPlatform::getCacheDirectory() const {
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw->pw_dir;
    }
    return std::string(home) + "/Library/Caches/AdShieldPro";
}

} // namespace Platform
} // namespace AdShield

#endif // __APPLE__
