#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <memory>
#include <sstream>

namespace AdShield {
namespace Core {

/**
 * @enum LogLevel
 * @brief Logging severity levels
 */
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

/**
 * @class Logger
 * @brief Thread-safe logging system
 * 
 * Provides:
 * - Multiple log levels
 * - File and console output
 * - Timestamp and context information
 * - Configurable verbosity
 */
class Logger {
public:
    static Logger& getInstance();
    
    void setLogLevel(LogLevel level);
    void setLogFile(const std::string& filepath);
    void enableConsoleOutput(bool enable);
    
    void debug(const std::string& message);
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);

private:
    Logger();
    ~Logger();
    
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    mutable std::mutex log_mutex;
    std::ofstream log_file;
    LogLevel current_level{LogLevel::INFO};
    bool console_output_enabled{true};
    
    void log(LogLevel level, const std::string& message);
    std::string getTimestamp() const;
    std::string getLevelString(LogLevel level) const;
};

} // namespace Core
} // namespace AdShield
