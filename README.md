# 🚀 WebSocket Messenger

Высокопроизводительный WebSocket сервер на C++17 с использованием Boost.Beast.

## ✨ Возможности

- ⚡ Асинхронный WebSocket сервер
- 🔐 Простая токен-авторизация
- 📝 Логирование в файл
- 🧵 Многопоточность
- 🌐 Кроссплатформенность (Windows/Linux/macOS)

## 🛠️ Сборка

### Требования
- C++17 совместимый компилятор
- CMake 3.16+
- Git

#### Ручная установка 

1. Установите vcpkg:
```
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh  # Linux/macOS
# или
bootstrap-vcpkg.bat   # Windows
```
2. Установите зависимости:
```
vcpkg install boost-beast:x64-windows boost-asio:x64-windows boost-system:x64-windows boost-thread:x64-windows openssl:x64-windows nlohmann-json:x64-windows
```
3. Соберите проект
```
mkdir build && cd build
cmake .. "-DCMAKE_TOOLCHAIN_FILE=../vcpkg/scripts/buildsystems/vcpkg.cmake" -DCMAKE_BUILD_TYPE=Release -G "MinGW Makefiles"
cmake --build . --config Release
```
4. Запуск
```
cd build
./WebSocketServer 0.0.0.0 8080 4
```
Откройте в браузере: http://localhost:8080/web/client.html
