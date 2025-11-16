#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <memory>

namespace AdShield {
namespace Core {

/**
 * @template Cache
 * @brief Thread-safe LRU cache with TTL support
 * 
 * Generic cache implementation with:
 * - Least Recently Used (LRU) eviction
 * - Time-To-Live (TTL) expiration
 * - Thread-safe operations
 * - Statistics tracking
 */
template<typename K, typename V>
class Cache {
private:
    struct CacheNode {
        K key;
        V value;
        std::chrono::steady_clock::time_point timestamp;
        CacheNode* next;
        CacheNode* prev;
        
        CacheNode(const K& k, const V& v) 
            : key(k), value(v), 
              timestamp(std::chrono::steady_clock::now()), 
              next(nullptr), prev(nullptr) {}
    };

public:
    explicit Cache(size_t capacity = 100000, 
                   std::chrono::seconds ttl = std::chrono::hours(1))
        : capacity(capacity), size(0), ttl(ttl), head(nullptr), tail(nullptr) {}
    
    ~Cache() { clear(); }

    void put(const K& key, const V& value);
    bool get(const K& key, V& value);
    void clear();
    
    size_t getSize() const { return size; }
    size_t getCapacity() const { return capacity; }

private:
    mutable std::mutex cache_mutex;
    std::unordered_map<K, CacheNode*> cache_map;
    CacheNode* head;
    CacheNode* tail;
    size_t capacity;
    size_t size;
    std::chrono::seconds ttl;
    
    void addToFront(CacheNode* node);
    void removeNode(CacheNode* node);
    void moveToFront(CacheNode* node);
    void removeLRU();
    void cleanupExpired();
};

} // namespace Core
} // namespace AdShield
