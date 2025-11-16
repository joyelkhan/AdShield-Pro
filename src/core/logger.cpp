#include "../../include/core/logger.hpp"
#include <iostream>
#include <iomanip>
#include <ctime>

namespace AdShield {
namespace Core {

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() {
    // Initialize with default settings
}

Logger::~Logger() {
    if (log_file.is_open()) {
        log_file.close();
    }
}

void Logger::setLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(log_mutex);
    current_level = level;
}

void Logger::setLogFile(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(log_mutex);
    
    if (log_file.is_open()) {
        log_file.close();
    }
    
    log_file.open(filepath, std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "Failed to open log file: " << filepath << std::endl;
    }
}

void Logger::enableConsoleOutput(bool enable) {
    std::lock_guard<std::mutex> lock(log_mutex);
    console_output_enabled = enable;
}

void Logger::debug(const std::string& message) {
    log(LogLevel::DEBUG, message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::WARNING, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

void Logger::critical(const std::string& message) {
    log(LogLevel::CRITICAL, message);
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < current_level) return;
    
    std::lock_guard<std::mutex> lock(log_mutex);
    
    std::string timestamp = getTimestamp();
    std::string level_str = getLevelString(level);
    std::string formatted = "[" + timestamp + "] [" + level_str + "] " + message;
    
    if (console_output_enabled) {
        std::cout << formatted << std::endl;
    }
    
    if (log_file.is_open()) {
        log_file << formatted << std::endl;
        log_file.flush();
    }
}

std::string Logger::getTimestamp() const {
    auto now = std::time(nullptr);
    auto tm = std::localtime(&now);
    
    std::ostringstream oss;
    oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string Logger::getLevelString(LogLevel level) const {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

} // namespace Core
} // namespace AdShield
