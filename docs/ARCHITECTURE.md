# AdShield Pro Ultra - Architecture Documentation

## Overview

AdShield Pro Ultra is a modular, multi-platform ad-blocking and privacy protection system designed with enterprise-grade architecture principles. The system is organized into distinct layers with clear separation of concerns.

## Architecture Layers

### 1. Core Layer (`include/core/`, `src/core/`)

The core layer provides fundamental functionality independent of platform or deployment context.

#### Components

**Configuration Management** (`config.hpp/cpp`)
- Thread-safe configuration loading and saving
- Support for multiple configuration formats
- Runtime configuration modification
- Default configuration initialization

**Logging System** (`logger.hpp/cpp`)
- Singleton logger instance
- Multiple log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- File and console output
- Timestamp and context information
- Thread-safe operations

**DNS Resolver** (`dns_resolver.hpp/cpp`)
- High-performance DNS resolution
- Domain blocking at DNS level
- Multiple upstream DNS server support
- Intelligent caching with TTL
- Statistics tracking (cache hits/misses, blocked count)

**Content Filter** (`content_filter.hpp/cpp`)
- Pattern-based content filtering
- Ad blocking (regex patterns)
- Tracker blocking
- Malware protection
- Custom user rules
- HTML content sanitization

**Cryptographic Engine** (`crypto.hpp/cpp`)
- AES-256-CTR encryption/decryption
- SHA-256 hashing
- Secure random number generation
- Certificate verification
- Signature validation

**Caching System** (`cache.hpp`)
- Generic LRU cache template
- TTL-based expiration
- Thread-safe operations
- Automatic cleanup of expired entries

**Main Controller** (`controller.hpp/cpp`)
- Orchestrates all core components
- Manages worker thread pool
- Coordinates DNS resolution and content filtering
- Statistics aggregation
- Lifecycle management

### 2. Platform Layer (`include/platform/`, `src/platform/`)

The platform layer provides platform-specific implementations while maintaining a consistent interface.

#### Platform Interface (`platform.hpp`)
- Abstract base class defining platform operations
- Service/daemon management
- Network interception setup
- System directory management
- Factory pattern for platform instantiation

#### Platform Implementations

**Windows** (`windows_platform.hpp/cpp`)
- Windows Service installation/removal
- WinDivert-based network interception
- Registry-based configuration
- System tray integration support

**Linux** (`linux_platform.hpp/cpp`)
- systemd service management
- iptables/netfilter network interception
- XDG Base Directory Specification compliance
- systemctl integration

**macOS** (`macos_platform.hpp/cpp`)
- launchd service management
- pfctl-based network interception
- macOS sandbox compatibility
- Gatekeeper and notarization support

### 3. Blocklist Management Layer (`include/blocklists/`, `src/blocklists/`)

**BlockListManager** (`blocklist_manager.hpp/cpp`)
- Multi-source blocklist aggregation
- Automatic blocklist updates
- Multiple format support (hosts, AdBlock, dnsmasq)
- Statistics and monitoring
- Incremental updates

Supported Sources:
- AdAway
- StevenBlack
- Malware Domain List
- Yoyo
- MVPS
- Custom user lists

### 4. Application Layer

**Main Entry Point** (`src/main/main.cpp`)
- CLI interface
- Command-line argument parsing
- Service mode handling
- Interactive command loop

## Data Flow

```
User Input (CLI/Config)
    ↓
Configuration Manager
    ↓
AdShield Controller
    ├─→ DNS Resolver
    │   ├─→ Blocklist Manager
    │   ├─→ DNS Cache
    │   └─→ Upstream DNS Servers
    ├─→ Content Filter
    │   ├─→ Pattern Matcher
    │   ├─→ Custom Rules
    │   └─→ HTML Sanitizer
    ├─→ Crypto Engine
    │   ├─→ Encryption/Decryption
    │   └─→ Hashing
    └─→ Platform Layer
        ├─→ Network Interception
        ├─→ Service Management
        └─→ System Integration
    ↓
Network Traffic Processing
    ↓
Logging & Statistics
```

## Threading Model

### Worker Thread Pool
- Configurable number of worker threads (default: CPU count)
- Task queue-based work distribution
- Condition variable synchronization
- Graceful shutdown handling

### Thread Safety
- Mutex protection for shared resources
- Lock-free atomics for counters
- Thread-safe singleton patterns
- RAII-based resource management

## Memory Management

### Strategies
- Stack allocation for small objects
- Smart pointers (unique_ptr, shared_ptr) for dynamic allocation
- Object pooling for frequently allocated objects
- LRU cache with automatic eviction
- Memory-mapped file support for large blocklists

### Performance Optimizations
- Zero-copy operations where possible
- String interning for domain names
- Bloom filters for fast domain lookup
- Lazy evaluation of patterns

## Configuration Management

### Configuration Hierarchy
1. Default values (hardcoded)
2. Configuration file (`adshield.conf`)
3. Environment variables
4. Runtime modifications

### Configuration File Format
```ini
# Section: DNS
dns_blocking_enabled=true
dns_timeout=3000

# Section: Filtering
https_filtering_enabled=true
block_trackers=true

# Section: Performance
cache_size=100000
compression_level=9
```

## Security Architecture

### Defense in Depth
1. **Input Validation**: All external input validated
2. **Encryption**: AES-256-CTR for sensitive data
3. **Hashing**: SHA-256 for integrity verification
4. **Sandboxing**: Platform-specific sandboxing
5. **Minimal Privileges**: Principle of least privilege
6. **Secure Defaults**: Security-first configuration

### Threat Model
- Protection against DNS hijacking
- Protection against man-in-the-middle attacks
- Protection against malware injection
- Protection against privacy leaks
- Protection against denial-of-service attacks

## Scalability Considerations

### Horizontal Scaling
- Stateless design for easy distribution
- Shared blocklist cache
- Load balancing support

### Vertical Scaling
- Multi-threaded architecture
- Efficient memory usage
- CPU-bound optimization
- I/O optimization

## Extension Points

### Adding New Blocklist Sources
1. Implement parser in `BlockListManager`
2. Add source configuration
3. Register in `initializeDefaultSources()`

### Adding New Filtering Rules
1. Create pattern in `ContentFilter`
2. Add to appropriate pattern vector
3. Update statistics

### Adding New Platforms
1. Create platform class inheriting `PlatformInterface`
2. Implement platform-specific methods
3. Register in `PlatformFactory`

## Performance Characteristics

### Time Complexity
- DNS lookup (cached): O(1)
- DNS lookup (uncached): O(log n) where n = blocklist size
- Content filtering: O(m) where m = number of patterns
- Blocklist update: O(n log n) where n = blocklist size

### Space Complexity
- Blocklist storage: O(n) where n = number of domains
- DNS cache: O(c) where c = cache capacity
- Pattern storage: O(p) where p = number of patterns

## Deployment Models

### Standalone
- Single machine installation
- Local DNS interception
- CLI-based management

### Service-Based
- System service/daemon
- Automatic startup
- Background operation

### Enterprise
- Centralized management
- Multiple machines
- Distributed blocklists
- Advanced monitoring

## Monitoring and Observability

### Metrics
- DNS queries blocked
- HTTP requests filtered
- Cache hit rate
- Memory usage
- CPU usage
- Uptime

### Logging
- Structured logging
- Multiple log levels
- File and console output
- Rotation support

### Statistics
- Real-time statistics
- Historical data
- Performance metrics
- Security events

## Future Enhancements

1. **Machine Learning**: Intelligent pattern detection
2. **Distributed Architecture**: Multi-node deployment
3. **Web Dashboard**: Visual management interface
4. **Mobile Apps**: Native iOS/Android applications
5. **VPN Integration**: Seamless VPN support
6. **Advanced Threat Detection**: AI-powered threat analysis
