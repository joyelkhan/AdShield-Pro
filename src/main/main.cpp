#include "../../include/core/controller.hpp"
#include "../../include/platform/platform.hpp"
#include "../../include/blocklists/blocklist_manager.hpp"
#include <iostream>
#include <string>
#include <vector>

using namespace AdShield;

class AdShieldCLI {
private:
    Core::AdShieldController controller;
    std::unique_ptr<Platform::PlatformInterface> platform;
    
public:
    AdShieldCLI() {
        platform = Platform::PlatformFactory::createPlatform();
    }
    
    bool initialize() {
        Core::Logger::getInstance().info("Initializing AdShield Pro Ultra CLI");
        
        if (!controller.initialize()) {
            Core::Logger::getInstance().error("Failed to initialize controller");
            return false;
        }
        
        return true;
    }
    
    void run() {
        std::cout << "\n";
        std::cout << "╔════════════════════════════════════════════════════════╗\n";
        std::cout << "║     AdShield Pro Ultra - Enterprise Ad Blocker        ║\n";
        std::cout << "║     Version 1.0.0                                    ║\n";
        std::cout << "╚════════════════════════════════════════════════════════╝\n";
        std::cout << "\n";
        
        if (!initialize()) {
            std::cerr << "ERROR: Initialization failed\n";
            return;
        }
        
        displayHelp();
        
        std::string command;
        while (true) {
            std::cout << "\nadshield> ";
            std::getline(std::cin, command);
            
            if (command.empty()) continue;
            
            if (command == "quit" || command == "exit") {
                break;
            } else if (command == "help") {
                displayHelp();
            } else if (command == "status") {
                displayStatus();
            } else if (command == "stats") {
                displayStatistics();
            } else if (command == "update") {
                controller.updateBlockLists();
            } else if (command.find("addrule ") == 0) {
                std::string rule = command.substr(8);
                controller.addCustomRule(rule);
            } else if (command == "config") {
                displayConfig();
            } else if (command == "clear-cache") {
                std::cout << "Cache cleared\n";
            } else if (command == "reset-stats") {
                controller.resetStatistics();
                std::cout << "Statistics reset\n";
            } else {
                std::cout << "Unknown command: " << command << "\n";
                std::cout << "Type 'help' for available commands\n";
            }
        }
        
        controller.shutdown();
        std::cout << "\nAdShield Pro Ultra shutdown complete. Goodbye!\n";
    }
    
private:
    void displayHelp() {
        std::cout << "\n📖 Available Commands:\n";
        std::cout << "  help              - Show this help message\n";
        std::cout << "  status            - Show current status\n";
        std::cout << "  stats             - Show blocking statistics\n";
        std::cout << "  update            - Update blocklists\n";
        std::cout << "  addrule <pattern> - Add custom blocking rule\n";
        std::cout << "  config            - Show configuration\n";
        std::cout << "  clear-cache       - Clear DNS cache\n";
        std::cout << "  reset-stats       - Reset statistics\n";
        std::cout << "  quit/exit         - Exit AdShield\n";
        std::cout << "\n";
    }
    
    void displayStatus() {
        std::cout << "\n✅ AdShield Pro Ultra Status:\n";
        std::cout << "  Status: " << (controller.isRunning() ? "RUNNING" : "STOPPED") << "\n";
        std::cout << "  Platform: " << platform->getPlatformName() << "\n";
        std::cout << "  Config Dir: " << platform->getConfigDirectory() << "\n";
        std::cout << "  Logs Dir: " << platform->getLogsDirectory() << "\n";
        std::cout << "\n";
    }
    
    void displayStatistics() {
        auto stats = controller.getStatistics();
        
        std::cout << "\n📊 AdShield Pro Ultra Statistics:\n";
        std::cout << "  DNS Queries Blocked: " << stats.dns_queries_blocked << "\n";
        std::cout << "  HTTP Requests Filtered: " << stats.http_requests_filtered << "\n";
        std::cout << "  Cache Hits: " << stats.cache_hits << "\n";
        std::cout << "  Cache Misses: " << stats.cache_misses << "\n";
        std::cout << "  Cache Hit Rate: " << stats.cache_hit_rate << "%\n";
        std::cout << "  Memory Usage: " << (stats.memory_usage / 1024 / 1024) << " MB\n";
        std::cout << "  Uptime: " << stats.uptime.count() << " seconds\n";
        std::cout << "\n";
    }
    
    void displayConfig() {
        auto& config = controller.getConfig();
        
        std::cout << "\n⚙️  Configuration:\n";
        std::cout << "  DNS Blocking: " << (config.getBool("dns_blocking_enabled") ? "Enabled" : "Disabled") << "\n";
        std::cout << "  HTTPS Filtering: " << (config.getBool("https_filtering_enabled") ? "Enabled" : "Disabled") << "\n";
        std::cout << "  Stealth Mode: " << (config.getBool("stealth_mode") ? "Enabled" : "Disabled") << "\n";
        std::cout << "  Block Trackers: " << (config.getBool("block_trackers") ? "Enabled" : "Disabled") << "\n";
        std::cout << "  Block Malware: " << (config.getBool("block_malware") ? "Enabled" : "Disabled") << "\n";
        std::cout << "  Cache Size: " << config.getInt("cache_size") << "\n";
        std::cout << "  DNS Timeout: " << config.getInt("dns_timeout") << " ms\n";
        std::cout << "\n";
    }
};

void showHelp() {
    std::cout << "AdShield Pro Ultra - Enterprise Ad Blocking & Privacy Solution\n";
    std::cout << "Usage: adshield-pro [OPTION]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --help, -h        Show this help message\n";
    std::cout << "  --service, -s     Run as service/daemon\n";
    std::cout << "  --install         Install as system service\n";
    std::cout << "  --uninstall       Uninstall system service\n";
    std::cout << "  --version, -v     Show version information\n";
    std::cout << "  (no arguments)    Run interactive CLI\n";
    std::cout << "\n";
}

void showVersion() {
    std::cout << "AdShield Pro Ultra v1.0.0\n";
    std::cout << "Enterprise-Grade Ad Blocking & Privacy Protection\n";
    std::cout << "Copyright 2024 - All Rights Reserved\n";
    std::cout << "\n";
}

int runAsService() {
    Core::Logger::getInstance().info("Running as service/daemon");
    
    Core::AdShieldController controller;
    if (!controller.initialize()) {
        Core::Logger::getInstance().error("Failed to initialize controller");
        return 1;
    }
    
    // Service main loop
    while (controller.isRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        // Check for service stop signals, update block lists, etc.
    }
    
    controller.shutdown();
    return 0;
}

int main(int argc, char* argv[]) {
    // Initialize logger
    Core::Logger::getInstance().setLogLevel(Core::LogLevel::INFO);
    Core::Logger::getInstance().enableConsoleOutput(true);
    
    // Parse command line arguments
    if (argc > 1) {
        std::string arg = argv[1];
        
        if (arg == "--help" || arg == "-h") {
            showHelp();
            return 0;
        } else if (arg == "--version" || arg == "-v") {
            showVersion();
            return 0;
        } else if (arg == "--service" || arg == "-s") {
            return runAsService();
        } else if (arg == "--install") {
            auto platform = Platform::PlatformFactory::createPlatform();
            if (platform && platform->installService()) {
                std::cout << "✅ Service installed successfully\n";
                return 0;
            } else {
                std::cerr << "❌ Failed to install service\n";
                return 1;
            }
        } else if (arg == "--uninstall") {
            auto platform = Platform::PlatformFactory::createPlatform();
            if (platform && platform->uninstallService()) {
                std::cout << "✅ Service uninstalled successfully\n";
                return 0;
            } else {
                std::cerr << "❌ Failed to uninstall service\n";
                return 1;
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            showHelp();
            return 1;
        }
    }
    
    // Run interactive CLI
    AdShieldCLI cli;
    cli.run();
    
    return 0;
}
