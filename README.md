<div align="center">

# 🚀 WebSocket Messenger

Лёгкий многопользовательский чат-сервер на C++ с поддержкой комнат и UTF-8

[![C++17](https://img.shields.io/badge/C++-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Boost](https://img.shields.io/badge/Boost-1.78+-green.svg)](https://www.boost.org/)
[![WebSocket](https://img.shields.io/badge/WebSocket-RFC6455-orange.svg)](https://tools.ietf.org/html/rfc6455)
![CMake 3.16+](https://img.shields.io/badge/CMake-3.16%2B-blue)
![Windows/Linux](https://img.shields.io/badge/OS-Windows%20%7C%20Linux-lightgrey)


</div>

---

## ✨ Возможности

### 🏠 **Система комнат**
- Изоляция сообщений по комнатам (пользователи видят только сообщения своей комнаты)
- История сообщений для каждой комнаты отдельно
- Простое переключение между комнатами через UI

### 🌍 **Поддержка UTF-8**
- Корректная валидация имён пользователей с кириллицей
- Подсчёт длины имени по символам, а не по байтам
- Без использования deprecated std::codecvt API

### 📊 **Продвинутое логирование**
- Структурированные логи через spdlog
- Ротация файлов логов (до 5MB, 3 файла)
- Цветной вывод в консоль
- Метрики подключений и производительности

### 🔧 **Надёжная архитектура**
- Многопоточность с Boost.Asio
- Graceful shutdown по SIGINT/SIGTERM
- Валидация входящих данных
- Защита от переполнения сообщений

### 🎨 **Современный UI**
- Отзывчивый дизайн
- Индикаторы состояния подключения
- Уведомления о входе/выходе пользователей
- Контроль входа в комнаты

---

## 🚀 Быстрый старт

### Системные требования
- **CMake** 3.20+
- **Компилятор C++17**: GCC 8+, Clang 9+, MSVC 2019+
- **Git** для vcpkg

### 1. Установка vcpkg
```bash
# Клонировать vcpkg в любое удобное место(рекомендую в папку проекта)
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg

# Собрать vcpkg 
./bootstrap-vcpkg.sh  # Linux/macOS
# или
./bootstrap-vcpkg.bat  # Windows
```

### 2. Установка зависимостей через vcpkg

```bash
# Установить пакеты
./vcpkg/vcpkg install boost-beast
./vcpkg/vcpkg install boost-system  
./vcpkg/vcpkg install boost-thread
./vcpkg/vcpkg install boost-program-options
./vcpkg/vcpkg install openssl
./vcpkg/vcpkg install nlohmann-json
./vcpkg/vcpkg install spdlog
./vcpkg/vcpkg install utfcpp
```

### 2. Сборка проекта

```bash
# Создать директорию сборки
mkdir build && cd build

# Конфигурация с vcpkg toolchain
cmake .. -DCMAKE_TOOLCHAIN_FILE=../vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_BUILD_TYPE=Release

# Сборка
cmake --build . --config Release -j
```

### 3. Запуск сервера

```bash
# Из директории build/
./WebSocketServer

# Или с параметрами
./WebSocketServer --host 0.0.0.0 --port 9090 --threads 8 --log-level DEBUG
```

### 4. Открыть клиент

Откройте `build/web/index.html` в браузере или разместите файлы на веб-сервере.

---

## 🛠️ Конфигурация

### Параметры сервера

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `--host` | `127.0.0.1` | IP-адрес для прослушивания |
| `--port` | `8080` | Порт для WebSocket |
| `--threads` | `auto` | Количество рабочих потоков |
| `--log-level` | `INFO` | Уровень логирования (DEBUG/INFO/WARN/ERROR) |
| `--log-file` | `server.log` | Путь к файлу логов |
| `--help` | - | Показать справку |

### Конфигурация клиента

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

## 📋 API WebSocket

### Аутентификация
```json
{"type": "auth", "token": "Bearer mytoken", "username": "Пользователь"}
```

### Отправка сообщения
```json
{"type": "message", "message": "Привет!"}
```

### Вход в комнату
```json
{"type": "join_room", "room": "general"}
```

### События от сервера
- `user_joined` — пользователь присоединился
- `user_left` — пользователь покинул чат
- `room_history` — история комнаты при входе
- `broadcast` — сообщение от другого пользователя

---

## 🧪 Тестирование

### Проверка разделения комнат
1. Откройте 2 вкладки браузера
2. Авторизуйтесь разными именами
3. Переведите одного пользователя в комнату "test"
4. Отправьте сообщения — они не должны пересекаться

### Проверка UTF-8
- Введите имя с кириллицей: `Даниил`, `Привет123`
- Проверьте валидацию длины (мин. 3, макс. 20 символов)

---

## 🔧 Разработка

### Структура проекта
```
WebSocketMassenger/
├── src/
│   ├── server/           # Серверная часть
│   │   ├── main.cpp      # Основная логика + SessionManager
│   │   ├── config.cpp    # Парсинг аргументов командной строки
│   │   └── logger.cpp    # Обёртка над spdlog
│   └── web/              # Клиентская часть
│       ├── index.html    # UI
│       ├── css/style.css # Стили
│       └── js/           # JavaScript логика
├── vcpkg/                # Менеджер пакетов
└── CMakeLists.txt        # Система сборки
```

### Зависимости
- **Boost.Beast** — WebSocket и HTTP
- **Boost.Asio** — Асинхронные операции
- **Boost.Program_options** — Парсинг CLI
- **nlohmann/json** — JSON парсинг
- **spdlog** — Логирование
- **utf8cpp** — UTF-8 валидация
- **OpenSSL** — Криптография (для Boost)

---

## 📊 Производительность

- **Память**: ~2MB в режиме покоя
- **Подключения**: протестировано до 100 одновременных
- **Latency**: <5ms для локальной сети
- **Пропускная способность**: зависит от сетевого стека

---

## 🤝 Вклад в проект

1. Форкните репозиторий
2. Создайте ветку фичи: `git checkout -b feature/awesome-feature`
3. Зафиксируйте изменения: `git commit -m 'feat: добавить awesome-feature'`
4. Отправьте в ветку: `git push origin feature/awesome-feature`
5. Откройте Pull Request

---

<div align="center">

**Если этот проект вам полезен — поставьте звёздочку ⭐ и поделитесь ссылкой!**

</div>
