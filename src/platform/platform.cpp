#include "../../include/platform/platform.hpp"
#include "../../include/core/logger.hpp"

#ifdef _WIN32
    #include "../../include/platform/windows_platform.hpp"
#elif defined(__linux__)
    #include "../../include/platform/linux_platform.hpp"
#elif defined(__APPLE__)
    #include "../../include/platform/macos_platform.hpp"
#endif

namespace AdShield {
namespace Platform {

std::unique_ptr<PlatformInterface> PlatformFactory::createPlatform() {
    Core::Logger::getInstance().info("Creating platform-specific implementation");
    
#ifdef _WIN32
    Core::Logger::getInstance().info("Detected Windows platform");
    return std::make_unique<WindowsPlatform>();
#elif defined(__linux__)
    Core::Logger::getInstance().info("Detected Linux platform");
    return std::make_unique<LinuxPlatform>();
#elif defined(__APPLE__)
    Core::Logger::getInstance().info("Detected macOS platform");
    return std::make_unique<MacOSPlatform>();
#else
    Core::Logger::getInstance().error("Unsupported platform");
    return nullptr;
#endif
}

PlatformType PlatformFactory::getCurrentPlatform() {
#ifdef _WIN32
    return PlatformType::WINDOWS;
#elif defined(__linux__)
    return PlatformType::LINUX;
#elif defined(__APPLE__)
    return PlatformType::MACOS;
#else
    return PlatformType::WINDOWS;  // Default fallback
#endif
}

} // namespace Platform
} // namespace AdShield
