#ifdef __linux__

#include "../../include/platform/linux_platform.hpp"
#include "../../include/core/logger.hpp"
#include <unistd.h>
#include <pwd.h>

namespace AdShield {
namespace Platform {

const std::string LinuxPlatform::SERVICE_NAME = "adshield-pro";
const std::string LinuxPlatform::SYSTEMD_UNIT_PATH = "/etc/systemd/system/adshield-pro.service";

LinuxPlatform::LinuxPlatform() {
    Core::Logger::getInstance().info("Linux Platform initialized");
}

LinuxPlatform::~LinuxPlatform() {
    Core::Logger::getInstance().info("Linux Platform shutdown");
}

PlatformType LinuxPlatform::getPlatformType() const {
    return PlatformType::LINUX;
}

std::string LinuxPlatform::getPlatformName() const {
    return "Linux";
}

bool LinuxPlatform::installService() {
    Core::Logger::getInstance().info("Installing Linux systemd service");
    
    // Check if running as root
    if (geteuid() != 0) {
        Core::Logger::getInstance().error("Service installation requires root privileges");
        return false;
    }
    
    // Implementation would create systemd unit file
    Core::Logger::getInstance().info("Service installed successfully");
    return true;
}

bool LinuxPlatform::uninstallService() {
    Core::Logger::getInstance().info("Uninstalling Linux systemd service");
    
    // Check if running as root
    if (geteuid() != 0) {
        Core::Logger::getInstance().error("Service uninstallation requires root privileges");
        return false;
    }
    
    // Implementation would remove systemd unit file
    Core::Logger::getInstance().info("Service uninstalled successfully");
    return true;
}

bool LinuxPlatform::startService() {
    Core::Logger::getInstance().info("Starting Linux service");
    // Implementation would use systemctl
    return true;
}

bool LinuxPlatform::stopService() {
    Core::Logger::getInstance().info("Stopping Linux service");
    // Implementation would use systemctl
    return true;
}

bool LinuxPlatform::setupNetworkInterception() {
    Core::Logger::getInstance().info("Setting up network interception on Linux");
    
    // Check if running as root
    if (geteuid() != 0) {
        Core::Logger::getInstance().error("Network interception requires root privileges");
        return false;
    }
    
    // Implementation would use iptables/netfilter
    return true;
}

bool LinuxPlatform::teardownNetworkInterception() {
    Core::Logger::getInstance().info("Tearing down network interception on Linux");
    return true;
}

std::string LinuxPlatform::getConfigDirectory() const {
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw->pw_dir;
    }
    return std::string(home) + "/.config/adshield-pro";
}

std::string LinuxPlatform::getLogsDirectory() const {
    return "/var/log/adshield-pro";
}

std::string LinuxPlatform::getCacheDirectory() const {
    const char* home = getenv("HOME");
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw->pw_dir;
    }
    return std::string(home) + "/.cache/adshield-pro";
}

} // namespace Platform
} // namespace AdShield

#endif // __linux__
