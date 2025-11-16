#ifdef _WIN32

#include "../../include/platform/windows_platform.hpp"
#include "../../include/core/logger.hpp"
#include <windows.h>
#include <shlobj.h>

namespace AdShield {
namespace Platform {

const std::string WindowsPlatform::SERVICE_NAME = "AdShieldPro";
const std::string WindowsPlatform::SERVICE_DISPLAY_NAME = "AdShield Pro Ultra - Ad Blocker Service";

WindowsPlatform::WindowsPlatform() {
    Core::Logger::getInstance().info("Windows Platform initialized");
}

WindowsPlatform::~WindowsPlatform() {
    Core::Logger::getInstance().info("Windows Platform shutdown");
}

PlatformType WindowsPlatform::getPlatformType() const {
    return PlatformType::WINDOWS;
}

std::string WindowsPlatform::getPlatformName() const {
    return "Windows";
}

bool WindowsPlatform::installService() {
    Core::Logger::getInstance().info("Installing Windows service");
    
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!schSCManager) {
        Core::Logger::getInstance().error("Failed to open Service Control Manager");
        return false;
    }
    
    char path[MAX_PATH];
    if (GetModuleFileName(NULL, path, MAX_PATH) == 0) {
        CloseServiceHandle(schSCManager);
        Core::Logger::getInstance().error("Failed to get module filename");
        return false;
    }
    
    std::string servicePath = std::string(path) + " --service";
    
    SC_HANDLE schService = CreateService(
        schSCManager,
        SERVICE_NAME.c_str(),
        SERVICE_DISPLAY_NAME.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        servicePath.c_str(),
        NULL, NULL, NULL, NULL, NULL
    );
    
    if (!schService) {
        CloseServiceHandle(schSCManager);
        Core::Logger::getInstance().error("Failed to create service");
        return false;
    }
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    
    Core::Logger::getInstance().info("Service installed successfully");
    return true;
}

bool WindowsPlatform::uninstallService() {
    Core::Logger::getInstance().info("Uninstalling Windows service");
    
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        Core::Logger::getInstance().error("Failed to open Service Control Manager");
        return false;
    }
    
    SC_HANDLE schService = OpenService(schSCManager, SERVICE_NAME.c_str(), DELETE);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        Core::Logger::getInstance().error("Failed to open service");
        return false;
    }
    
    bool result = DeleteService(schService);
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    
    if (result) {
        Core::Logger::getInstance().info("Service uninstalled successfully");
    } else {
        Core::Logger::getInstance().error("Failed to uninstall service");
    }
    
    return result;
}

bool WindowsPlatform::startService() {
    Core::Logger::getInstance().info("Starting Windows service");
    // Implementation would use Service Control Manager
    return true;
}

bool WindowsPlatform::stopService() {
    Core::Logger::getInstance().info("Stopping Windows service");
    // Implementation would use Service Control Manager
    return true;
}

bool WindowsPlatform::setupNetworkInterception() {
    Core::Logger::getInstance().info("Setting up network interception on Windows");
    // Implementation would use WinDivert or similar
    return true;
}

bool WindowsPlatform::teardownNetworkInterception() {
    Core::Logger::getInstance().info("Tearing down network interception on Windows");
    return true;
}

std::string WindowsPlatform::getConfigDirectory() const {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        return std::string(path) + "\\AdShieldPro";
    }
    return ".\\config";
}

std::string WindowsPlatform::getLogsDirectory() const {
    return getConfigDirectory() + "\\logs";
}

std::string WindowsPlatform::getCacheDirectory() const {
    return getConfigDirectory() + "\\cache";
}

} // namespace Platform
} // namespace AdShield

#endif // _WIN32
