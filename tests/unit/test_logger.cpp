#include <catch2/catch_test_macros.hpp>
#include "../../include/core/logger.hpp"

using namespace AdShield::Core;

TEST_CASE("Logger - Singleton Instance", "[logger]") {
    Logger& logger1 = Logger::getInstance();
    Logger& logger2 = Logger::getInstance();
    
    REQUIRE(&logger1 == &logger2);
}

TEST_CASE("Logger - Set Log Level", "[logger]") {
    Logger& logger = Logger::getInstance();
    
    logger.setLogLevel(LogLevel::DEBUG);
    logger.debug("Debug message");
    
    logger.setLogLevel(LogLevel::ERROR);
    logger.info("Info message");  // Should not be logged
}

TEST_CASE("Logger - Console Output Control", "[logger]") {
    Logger& logger = Logger::getInstance();
    
    logger.enableConsoleOutput(true);
    logger.info("Console enabled");
    
    logger.enableConsoleOutput(false);
    logger.info("Console disabled");
}

TEST_CASE("Logger - All Log Levels", "[logger]") {
    Logger& logger = Logger::getInstance();
    logger.setLogLevel(LogLevel::DEBUG);
    
    REQUIRE_NOTHROW(logger.debug("Debug message"));
    REQUIRE_NOTHROW(logger.info("Info message"));
    REQUIRE_NOTHROW(logger.warning("Warning message"));
    REQUIRE_NOTHROW(logger.error("Error message"));
    REQUIRE_NOTHROW(logger.critical("Critical message"));
}
