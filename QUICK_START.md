# ⚡ AdShield Pro v1.0 - Quick Start Guide

**Get up and running in 5 minutes!**

**Author:** MD Abu Naser Khan

---

## 🚀 Installation

### Windows (PowerShell)
```powershell
# 1. Clone
git clone https://github.com/yourusername/adsguard-ultra.git
cd "adsguard-ultra"

# 2. Build
.\scripts\build_all_platforms.ps1

# 3. Run
.\dist\windows\adsguard_ultra.exe
```

### macOS (Terminal)
```bash
# 1. Clone
git clone https://github.com/yourusername/adsguard-ultra.git
cd adsguard-ultra

# 2. Build
chmod +x scripts/build_all_platforms.sh
./scripts/build_all_platforms.sh

# 3. Run
./dist/macos/adsguard_ultra
```

### Linux (Terminal)
```bash
# 1. Install dependencies
sudo apt-get install cmake build-essential libssl-dev libcurl4-openssl-dev libre2-dev

# 2. Clone
git clone https://github.com/yourusername/adsguard-ultra.git
cd adsguard-ultra

# 3. Build
chmod +x scripts/build_all_platforms.sh
./scripts/build_all_platforms.sh

# 4. Run
./dist/linux/adsguard_ultra
```

---

## 📦 Pre-built Packages

### Linux
```bash
# Ubuntu/Debian
sudo dpkg -i adsguard-ultra-2.0.0-Linux.deb

# Fedora/RHEL
sudo rpm -i adsguard-ultra-2.0.0-Linux.rpm

# Run
adsguard_ultra
```

### macOS
```bash
# Mount DMG
hdiutil mount adsguard-ultra-2.0.0-Darwin.dmg

# Drag to Applications folder
# Run from Applications
```

### Windows
```powershell
# Run installer
.\adsguard-ultra-2.0.0-win64.exe

# Or extract portable ZIP
Expand-Archive adsguard-ultra-2.0.0-win64.zip
cd adsguard-ultra-2.0.0-win64
.\adsguard_ultra.exe
```

---

## 🔧 Build from Source

### Prerequisites
- **CMake** 3.20+
- **Git**
- **C++ Compiler** (GCC 11+, Clang 13+, MSVC 2022)
- **Dependencies**: OpenSSL, libcurl, re2

### Build Steps
```bash
# Clone repository
git clone https://github.com/yourusername/adsguard-ultra.git
cd adsguard-ultra

# Create build directory
mkdir build && cd build

# Configure
cmake -DCMAKE_BUILD_TYPE=Release ..

# Build
make -j$(nproc)  # Linux/macOS
cmake --build . --config Release -j 4  # Windows

# Install (optional)
sudo make install
```

---

## 🎯 Common Tasks

### Run Tests
```bash
cd build
ctest --output-on-failure
```

### Analyze Code
```bash
python3 scripts/analyze_codebase.py .
```

### Benchmark Performance
```bash
python3 scripts/performance_benchmark.py ./build/adsguard_ultra
```

### Profile Memory
```bash
valgrind --leak-check=full ./build/adsguard_ultra
```

### Create Packages
```bash
cd build
cpack -G "DEB;RPM;TGZ"  # Linux
cpack -G "DragNDrop;ZIP"  # macOS
cpack -G "NSIS;ZIP"  # Windows
```

---

## 📋 Configuration

### Basic Config (config.json)
```json
{
  "dns": {
    "providers": ["cloudflare", "quad9"],
    "protocols": ["doh", "doq"],
    "caching": true,
    "cache_ttl": 3600
  },
  "filtering": {
    "blocklists": [
      "https://adaway.org/hosts.txt"
    ],
    "categories": ["ads", "trackers"]
  },
  "security": {
    "tls_version": "1.3",
    "sandboxing": true,
    "telemetry": false
  }
}
```

### Run with Config
```bash
./adsguard_ultra --config config.json
```

---

## 🔌 API Quick Reference

### REST API
```bash
# Get statistics
curl http://localhost:8080/api/stats

# Get query log
curl http://localhost:8080/api/log?limit=100

# Toggle filtering
curl -X POST http://localhost:8080/api/toggle
```

### WebSocket
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');
ws.onmessage = (e) => console.log('Query:', e.data);
```

---

## 🐛 Troubleshooting

### Build Fails - Missing Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install cmake build-essential libssl-dev libcurl4-openssl-dev libre2-dev

# macOS
brew install cmake openssl libcurl re2

# Fedora/RHEL
sudo dnf install cmake gcc-c++ openssl-devel libcurl-devel re2-devel
```

### CMake Not Found
```bash
# Install CMake
# Ubuntu/Debian
sudo apt-get install cmake

# macOS
brew install cmake

# Windows (Chocolatey)
choco install cmake
```

### OpenSSL Not Found
```bash
# Linux
export OPENSSL_DIR=/usr/lib/ssl

# macOS
export OPENSSL_DIR=$(brew --prefix openssl)

# Windows
set OPENSSL_DIR=C:\OpenSSL
```

### Build Still Fails?
1. Check [BUILD_GUIDE.md](BUILD_GUIDE.md) for detailed instructions
2. Review [ARCHITECTURE.md](ARCHITECTURE.md) for system design
3. Open issue on GitHub with build output

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | Project overview |
| [BUILD_GUIDE.md](BUILD_GUIDE.md) | Detailed build instructions |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design & components |
| [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) | Complete project summary |
| [QUICK_START.md](QUICK_START.md) | This file |

---

## 🎓 Learning Path

1. **Start Here**: Read [README.md](README.md)
2. **Build It**: Follow [BUILD_GUIDE.md](BUILD_GUIDE.md)
3. **Understand It**: Study [ARCHITECTURE.md](ARCHITECTURE.md)
4. **Optimize It**: Run benchmarks and analysis
5. **Deploy It**: Create packages and distribute

---

## 🔗 Useful Links

- **GitHub**: https://github.com/yourusername/adsguard-ultra
- **Issues**: https://github.com/yourusername/adsguard-ultra/issues
- **Discussions**: https://github.com/yourusername/adsguard-ultra/discussions
- **Email**: support@adsguard.dev

---

## ⚡ Performance Tips

### For Maximum Performance
```bash
# Build with optimizations
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="-O3 -march=native -flto" ..
make -j$(nproc)
```

### For Development
```bash
# Build with debug symbols
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

### For Profiling
```bash
# Build with profiling support
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
make -j$(nproc)

# Profile
perf record -g ./adsguard_ultra
perf report
```

---

## 🔒 Security Checklist

- ✅ Use latest version
- ✅ Enable sandboxing
- ✅ Disable telemetry if not needed
- ✅ Use HTTPS/DoH for DNS
- ✅ Keep blocklists updated
- ✅ Review configuration regularly
- ✅ Monitor logs for issues

---

## 🆘 Getting Help

### Quick Help
1. Check this Quick Start guide
2. Search [GitHub Issues](https://github.com/yourusername/adsguard-ultra/issues)
3. Ask in [GitHub Discussions](https://github.com/yourusername/adsguard-ultra/discussions)

### Detailed Help
1. Read [BUILD_GUIDE.md](BUILD_GUIDE.md) for build issues
2. Read [ARCHITECTURE.md](ARCHITECTURE.md) for design questions
3. Read [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) for overview

### Report Issues
- Include OS and version
- Include build output
- Include configuration
- Include error messages

---

## 🎉 You're Ready!

You now have ADSGUARD Ultra installed and running! 🚀

Next steps:
1. Configure it for your needs
2. Add blocklists
3. Monitor the dashboard
4. Enjoy ad-free browsing!

---

**Version:** 1.0.0 | **Status:** ✅ Production Ready  
**Author:** MD Abu Naser Khan

**Made with ❤️ by MD Abu Naser Khan & AdShield Pro Team**
