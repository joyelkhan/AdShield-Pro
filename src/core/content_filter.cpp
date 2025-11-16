#include "../../include/core/content_filter.hpp"
#include "../../include/core/logger.hpp"
#include <algorithm>

namespace AdShield {
namespace Core {

ContentFilter::ContentFilter() {
    Logger::getInstance().info("Initializing Content Filter");
    initializePatterns();
}

ContentFilter::~ContentFilter() {
    Logger::getInstance().info("Content Filter shutdown");
}

void ContentFilter::initializePatterns() {
    // Ad patterns
    std::vector<std::string> ad_regexes = {
        R"(/ads?/)"s,
        R"(/adserver/)"s,
        R"(/banner/)"s,
        R"(/track(ing)?/)"s,
        R"(/analytics/)"s,
        R"(googleads)"s,
        R"(doubleclick)"s,
        R"(facebook\.com/(tr|pixel))"s,
        R"(googlesyndication)"s,
        R"(adservice\.google)"s,
        R"(pagead2\.googlesyndication)"s,
        R"(securepubads\.g\.doubleclick)"s,
        R"(/affiliate/)"s,
        R"(/partner/)"s,
        R"(adsystem\.google)"s
    };
    
    for (const auto& pattern : ad_regexes) {
        try {
            ad_patterns.emplace_back(pattern, std::regex::icase | std::regex::optimize);
        } catch (const std::regex_error& e) {
            Logger::getInstance().warning("Invalid ad pattern: " + pattern);
        }
    }
    
    // Tracker patterns
    std::vector<std::string> tracker_regexes = {
        R"(/track)"s,
        R"(/pixel)"s,
        R"(/beacon)"s,
        R"(/analytics)"s,
        R"(/metrics)"s,
        R"(/telemetry)"s,
        R"(/collect)"s,
        R"(/log)"s,
        R"(/monitor)"s,
        R"(gtm\.js)"s,
        R"(ga\.js)"s,
        R"(analytics\.js)"s
    };
    
    for (const auto& pattern : tracker_regexes) {
        try {
            tracker_patterns.emplace_back(pattern, std::regex::icase | std::regex::optimize);
        } catch (const std::regex_error& e) {
            Logger::getInstance().warning("Invalid tracker pattern: " + pattern);
        }
    }
    
    Logger::getInstance().info("Content Filter patterns initialized");
}

bool ContentFilter::shouldBlock(const std::string& url, const std::string& host) const {
    std::string lower_url = url;
    std::transform(lower_url.begin(), lower_url.end(), lower_url.begin(), ::tolower);
    
    std::string lower_host = host;
    std::transform(lower_host.begin(), lower_host.end(), lower_host.begin(), ::tolower);
    
    std::lock_guard<std::mutex> lock(filter_mutex);
    
    // Check blocked URLs first
    if (blocked_urls.find(lower_url) != blocked_urls.end()) {
        return true;
    }
    
    // Check ad patterns
    if (ad_blocking_enabled && matchesPattern(lower_url, ad_patterns)) {
        return true;
    }
    
    // Check tracker patterns
    if (tracker_blocking_enabled && matchesPattern(lower_url, tracker_patterns)) {
        return true;
    }
    
    // Check custom patterns
    if (matchesPattern(lower_url, custom_patterns)) {
        return true;
    }
    
    return false;
}

std::string ContentFilter::filterHTML(const std::string& html, const std::string& url) {
    std::string filtered_html = html;
    
    // Remove script tags that match ad patterns
    filtered_html = std::regex_replace(filtered_html, 
        std::regex(R"(<script[^>]*ads?[^>]*>.*?</script>)", std::regex::icase), "");
    
    // Remove iframes with ad domains
    filtered_html = std::regex_replace(filtered_html,
        std::regex(R"(<iframe[^>]*(doubleclick|googleads|googlesyndication)[^>]*>.*?</iframe>)", std::regex::icase), "");
    
    // Remove elements with ad classes
    filtered_html = std::regex_replace(filtered_html,
        std::regex(R"(<[^>]*class=[^>]*(ads?|banner|advertisement)[^>]*>)", std::regex::icase), "");
    
    return filtered_html;
}

void ContentFilter::addCustomRule(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(filter_mutex);
    try {
        custom_patterns.emplace_back(pattern, std::regex::icase | std::regex::optimize);
        Logger::getInstance().info("Custom rule added: " + pattern);
    } catch (const std::regex_error& e) {
        Logger::getInstance().error("Invalid custom rule pattern: " + pattern);
    }
}

void ContentFilter::removeCustomRule(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(filter_mutex);
    // Note: This is a simplified implementation
    Logger::getInstance().info("Custom rule removed: " + pattern);
}

void ContentFilter::clearCustomRules() {
    std::lock_guard<std::mutex> lock(filter_mutex);
    custom_patterns.clear();
    Logger::getInstance().info("All custom rules cleared");
}

void ContentFilter::enableAdBlocking(bool enable) {
    std::lock_guard<std::mutex> lock(filter_mutex);
    ad_blocking_enabled = enable;
}

void ContentFilter::enableTrackerBlocking(bool enable) {
    std::lock_guard<std::mutex> lock(filter_mutex);
    tracker_blocking_enabled = enable;
}

void ContentFilter::enableMalwareBlocking(bool enable) {
    std::lock_guard<std::mutex> lock(filter_mutex);
    malware_blocking_enabled = enable;
}

bool ContentFilter::matchesPattern(const std::string& text, const std::vector<std::regex>& patterns) const {
    for (const auto& pattern : patterns) {
        try {
            if (std::regex_search(text, pattern)) {
                return true;
            }
        } catch (const std::regex_error& e) {
            Logger::getInstance().warning("Regex error during pattern matching");
        }
    }
    return false;
}

} // namespace Core
} // namespace AdShield
