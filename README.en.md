<div align="center">

# 🚀 WebSocket Messenger

Lightweight multi-user chat server in C++ with room support and UTF-8

[![C++17](https://img.shields.io/badge/C++-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Boost](https://img.shields.io/badge/Boost-1.78+-green.svg)](https://www.boost.org/)
[![WebSocket](https://img.shields.io/badge/WebSocket-RFC6455-orange.svg)](https://tools.ietf.org/html/rfc6455)
![CMake 3.16+](https://img.shields.io/badge/CMake-3.16%2B-blue)
![Windows/Linux](https://img.shields.io/badge/OS-Windows%20%7C%20Linux-lightgrey)


[Русская версия](README.md)

</div>

---

## ✨ Features

### 🏠 **Room System**
- Message isolation by rooms (users only see messages from their current room)
- Separate message history for each room
- Easy room switching through UI

### 🌍 **UTF-8 Support**
- Proper username validation with Cyrillic characters
- Character-based length counting (not bytes)
- Modern implementation without deprecated std::codecvt API

### 📊 **Advanced Logging**
- Structured logging via spdlog
- Log file rotation (up to 5MB, 3 files)
- Colored console output
- Connection and performance metrics

### 🔧 **Robust Architecture**
- Multi-threading with Boost.Asio
- Graceful shutdown on SIGINT/SIGTERM
- Input data validation
- Message overflow protection

### 🎨 **Modern UI**
- Responsive design
- Connection status indicators
- User join/leave notifications
- Room control interface

---

## 🚀 Quick Start

### System Requirements
- **CMake** 3.20+
- **C++17 Compiler**: GCC 8+, Clang 9+, MSVC 2019+
- **Git** for vcpkg

### 1. Install Dependencies via vcpkg

```bash
# Clone repository (if vcpkg/ is missing)
git submodule update --init --recursive

# Install packages
./vcpkg/vcpkg install boost-beast
./vcpkg/vcpkg install boost-system  
./vcpkg/vcpkg install boost-thread
./vcpkg/vcpkg install boost-program-options
./vcpkg/vcpkg install openssl
./vcpkg/vcpkg install nlohmann-json
./vcpkg/vcpkg install spdlog
./vcpkg/vcpkg install utf8cpp
```

### 2. Build Project

```bash
# Create build directory
mkdir build && cd build

# Configure with vcpkg toolchain
cmake .. -DCMAKE_TOOLCHAIN_FILE=../vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build . --config Release -j
```

### 3. Run Server

```bash
# From build/ directory
./WebSocketServer

# Or with parameters
./WebSocketServer --host 0.0.0.0 --port 9090 --threads 8 --log-level DEBUG
```

### 4. Open Client

Open `build/web/index.html` in browser or host the files on a web server.

---

## 🛠️ Configuration

### Server Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--host` | `127.0.0.1` | IP address to listen on |
| `--port` | `8080` | WebSocket port |
| `--threads` | `auto` | Number of worker threads |
| `--log-level` | `INFO` | Log level (DEBUG/INFO/WARN/ERROR) |
| `--log-file` | `server.log` | Path to log file |
| `--help` | - | Show help |

### Client Configuration

```javascript
// src/web/js/config.js
const CONFIG = {
    WS_URL: "ws://localhost:8080",
    AUTH_TOKEN: "Bearer mytoken",
    PING_INTERVAL: 60000,
    RECONNECT_DELAY: 5000
};
```

---

## 📋 WebSocket API

### Authentication
```json
{"type": "auth", "token": "Bearer mytoken", "username": "User"}
```

### Send Message
```json
{"type": "message", "message": "Hello!"}
```

### Join Room
```json
{"type": "join_room", "room": "general"}
```

### Server Events
- `user_joined` — user joined the chat
- `user_left` — user left the chat
- `room_history` — room history on join
- `broadcast` — message from another user

---

## 🧪 Testing

### Room Isolation Test
1. Open 2 browser tabs
2. Authenticate with different usernames
3. Move one user to "test" room
4. Send messages — they should not cross between rooms

### UTF-8 Test
- Enter usernames with Cyrillic: `Даниил`, `Привет123`
- Check length validation (min 3, max 20 characters)

---

## 🔧 Development

### Project Structure
```
WebSocketMassenger/
├── src/
│   ├── server/           # Server-side code
│   │   ├── main.cpp      # Main logic + SessionManager
│   │   ├── config.cpp    # Command-line argument parsing
│   │   └── logger.cpp    # spdlog wrapper
│   └── web/              # Client-side code
│       ├── index.html    # UI
│       ├── css/style.css # Styles
│       └── js/           # JavaScript logic
├── vcpkg/                # Package manager
└── CMakeLists.txt        # Build system
```

### Dependencies
- **Boost.Beast** — WebSocket and HTTP
- **Boost.Asio** — Asynchronous operations
- **Boost.Program_options** — CLI parsing
- **nlohmann/json** — JSON parsing
- **spdlog** — Logging
- **utf8cpp** — UTF-8 validation
- **OpenSSL** — Cryptography (for Boost)

---

## 📊 Performance

- **Memory**: ~2MB at idle
- **Connections**: tested up to 100 concurrent
- **Latency**: <5ms for local network
- **Throughput**: depends on network stack

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/awesome-feature`
3. Commit changes: `git commit -m 'feat: add awesome-feature'`
4. Push to branch: `git push origin feature/awesome-feature`
5. Open Pull Request

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

<div align="center">

**If you find this project useful — give it a star ⭐ and share the link!**

</div>
