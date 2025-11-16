# AdShield Pro Ultra - Project Structure

## Directory Layout

```
adshield-pro-ultra/
│
├── include/                          # Header files (public API)
│   ├── core/                        # Core components
│   │   ├── config.hpp              # Configuration management
│   │   ├── dns_resolver.hpp        # DNS resolution and blocking
│   │   ├── content_filter.hpp      # Content filtering engine
│   │   ├── crypto.hpp              # Cryptographic operations
│   │   ├── cache.hpp               # LRU cache template
│   │   ├── logger.hpp              # Logging system
│   │   └── controller.hpp          # Main controller
│   │
│   ├── platform/                    # Platform abstraction layer
│   │   ├── platform.hpp            # Platform interface
│   │   ├── windows_platform.hpp    # Windows implementation
│   │   ├── linux_platform.hpp      # Linux implementation
│   │   └── macos_platform.hpp      # macOS implementation
│   │
│   └── blocklists/                  # Blocklist management
│       └── blocklist_manager.hpp   # Blocklist aggregation
│
├── src/                             # Implementation files
│   ├── core/                        # Core implementations
│   │   ├── config.cpp
│   │   ├── dns_resolver.cpp
│   │   ├── content_filter.cpp
│   │   ├── crypto.cpp
│   │   ├── logger.cpp
│   │   └── controller.cpp
│   │
│   ├── platform/                    # Platform implementations
│   │   ├── platform.cpp
│   │   ├── windows_platform.cpp
│   │   ├── linux_platform.cpp
│   │   └── macos_platform.cpp
│   │
│   ├── blocklists/                  # Blocklist implementations
│   │   └── blocklist_manager.cpp
│   │
│   └── main/                        # Application entry point
│       └── main.cpp
│
├── tests/                           # Test suite
│   ├── CMakeLists.txt              # Test build configuration
│   ├── unit/                        # Unit tests
│   │   ├── test_config.cpp
│   │   ├── test_logger.cpp
│   │   ├── test_dns_resolver.cpp
│   │   ├── test_content_filter.cpp
│   │   ├── test_cache.cpp
│   │   └── test_crypto.cpp
│   │
│   └── integration/                 # Integration tests (future)
│       └── test_controller.cpp
│
├── docs/                            # Documentation
│   ├── README.md                   # Main documentation
│   ├── ARCHITECTURE.md             # Architecture documentation
│   ├── BUILD.md                    # Build instructions
│   ├── FEATURES.md                 # Feature documentation
│   ├── API.md                      # API documentation (future)
│   └── DEPLOYMENT.md               # Deployment guide (future)
│
├── scripts/                         # Build and deployment scripts
│   ├── build.sh                    # Linux/macOS build script
│   ├── build.bat                   # Windows build script
│   ├── install.sh                  # Linux installation script
│   ├── install.bat                 # Windows installation script
│   └── deploy.sh                   # Deployment script (future)
│
├── resources/                       # Configuration and resources
│   ├── blocklists/                 # Default blocklists
│   │   └── sources.conf            # Blocklist sources
│   │
│   ├── certificates/               # SSL/TLS certificates
│   │   └── ca-bundle.crt
│   │
│   └── webui/                      # Web UI resources (future)
│       ├── index.html
│       ├── css/
│       └── js/
│
├── CMakeLists.txt                  # CMake build configuration
├── README.md                        # Project overview
├── STRUCTURE.md                     # This file
├── adshield.conf                   # Default configuration
├── .gitignore                      # Git ignore rules
├── LICENSE                         # License file
└── CHANGELOG.md                    # Version history

```

## File Organization Principles

### Header Files (`include/`)
- Public API definitions
- Organized by functional area
- No implementation details
- Clear documentation

### Implementation Files (`src/`)
- Organized to mirror header structure
- Implementation details hidden
- Modular and focused
- Well-commented

### Tests (`tests/`)
- Unit tests for each component
- Integration tests for workflows
- Test fixtures and utilities
- Organized by component

### Documentation (`docs/`)
- Comprehensive guides
- API documentation
- Architecture diagrams
- Deployment procedures

### Scripts (`scripts/`)
- Build automation
- Installation procedures
- Deployment utilities
- Platform-specific scripts

### Resources (`resources/`)
- Configuration templates
- Blocklist sources
- SSL certificates
- Web UI assets

## Component Dependencies

```
main.cpp
    ↓
AdShieldController
    ├─→ Configuration
    ├─→ DNSResolver
    │   ├─→ BlockListManager
    │   └─→ Cache
    ├─→ ContentFilter
    ├─→ CryptoEngine
    ├─→ Logger
    └─→ PlatformInterface
        ├─→ WindowsPlatform
        ├─→ LinuxPlatform
        └─→ MacOSPlatform
```

## Build Artifacts

After building, the following artifacts are created:

```
build/
├── bin/
│   └── adshield-pro              # Main executable
│
├── lib/
│   ├── libadshield_core.a        # Core library
│   ├── libadshield_platform.a    # Platform library
│   └── libadshield_blocklists.a  # Blocklist library
│
├── tests/
│   └── adshield_tests            # Test executable
│
└── CMakeFiles/
    └── ...                        # CMake artifacts
```

## Configuration Files

### Primary Configuration
- `adshield.conf` - Main configuration file

### Platform-Specific
- Windows: `%APPDATA%\AdShieldPro\adshield.conf`
- Linux: `~/.config/adshield-pro/adshield.conf`
- macOS: `~/Library/Application Support/AdShieldPro/adshield.conf`

## Log Files

### Default Locations
- Windows: `%APPDATA%\AdShieldPro\logs\`
- Linux: `/var/log/adshield-pro/`
- macOS: `~/Library/Logs/AdShieldPro/`

## Cache Directories

### Default Locations
- Windows: `%APPDATA%\AdShieldPro\cache\`
- Linux: `~/.cache/adshield-pro/`
- macOS: `~/Library/Caches/AdShieldPro/`

## Adding New Components

### Adding a New Core Component

1. Create header in `include/core/new_component.hpp`
2. Create implementation in `src/core/new_component.cpp`
3. Add to `CMakeLists.txt` build configuration
4. Create tests in `tests/unit/test_new_component.cpp`
5. Update documentation

### Adding a New Platform

1. Create header in `include/platform/new_platform.hpp`
2. Create implementation in `src/platform/new_platform.cpp`
3. Update `platform.cpp` factory
4. Add to `CMakeLists.txt` platform-specific section
5. Create tests in `tests/unit/test_new_platform.cpp`

## Naming Conventions

### Files
- Headers: `component_name.hpp`
- Implementation: `component_name.cpp`
- Tests: `test_component_name.cpp`

### Classes
- PascalCase: `ConfigurationManager`
- Namespaced: `AdShield::Core::Configuration`

### Functions/Methods
- camelCase: `loadConfiguration()`
- Private: prefix with underscore: `_internalMethod()`

### Variables
- snake_case: `config_file`
- Constants: UPPER_SNAKE_CASE: `MAX_CACHE_SIZE`

## Version Control

### Branch Strategy
- `main` - Stable releases
- `develop` - Development branch
- `feature/*` - Feature branches
- `bugfix/*` - Bug fix branches

### Commit Messages
- Format: `[TYPE] Description`
- Types: feat, fix, docs, style, refactor, test, chore
- Example: `[feat] Add DNS caching support`

## Documentation Standards

### Code Comments
- Explain "why", not "what"
- Use clear, concise language
- Document complex algorithms

### Function Documentation
- Brief description
- Parameter documentation
- Return value documentation
- Exception documentation

### File Headers
```cpp
/**
 * @file component_name.hpp
 * @brief Brief description of component
 * @details Detailed description
 * @author Author Name
 * @date Date
 */
```

## Performance Considerations

### Memory Layout
- Group related data together
- Minimize cache misses
- Use appropriate data structures

### Threading
- Minimize lock contention
- Use lock-free structures where possible
- Proper synchronization

### I/O Operations
- Batch operations
- Use buffering
- Asynchronous where appropriate
