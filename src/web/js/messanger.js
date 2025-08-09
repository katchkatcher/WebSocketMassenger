// === ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ===
let ws = null;
let isConnected = false;
let isAuthenticated = false;
let pingInterval = null;
let reconnectTimeout = null;

// === ЭЛЕМЕНТЫ DOM ===
let messagesList, messageInput, sendBtn, connectionStatus;
let connectionDot, authDot, pingDot;

// === УТИЛИТЫ ===
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(date) {
    return date.toLocaleTimeString('ru-RU', {
        hour: '2-digit',
        minute: '2-digit'
    });
}

// === WEBSOCKET ЛОГИКА ===
function connect() {
    updateConnectionStatus("Подключение...");

    try {
        ws = new WebSocket(CONFIG.WS_URL);

        ws.onopen = function () {
            console.log("✅ Подключен к серверу");
            isConnected = true;
            updateStatusIndicators();
            updateConnectionStatus("Авторизация...");
            sendAuth();
            startPing();
        };

        ws.onmessage = function (event) {
            try {
                const response = JSON.parse(event.data);
                handleMessage(response);
            } catch (error) {
                console.error("Ошибка парсинга JSON:", error);
                addSystemMessage("Получено некорректное сообщение");
            }
        };

        ws.onerror = function (error) {
            console.error("❌ Ошибка WebSocket:", error);
            updateConnectionStatus("Ошибка соединения");
            scheduleReconnect();
        };

        ws.onclose = function (event) {
            console.log("🔌 Соединение закрыто, код:", event.code);
            isConnected = false;
            isAuthenticated = false;
            updateStatusIndicators();
            updateConnectionStatus("Отключен");
            disableInput();
            stopPing();

            if (event.code !== 1000) {
                scheduleReconnect();
            }
        };

    } catch (error) {
        console.error("❌ Ошибка создания WebSocket:", error);
        updateConnectionStatus("Ошибка подключения");
        scheduleReconnect();
    }
}

function disconnect() {
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
    }

    if (ws) {
        ws.close(1000);
    }
}

function scheduleReconnect() {
    if (reconnectTimeout) return;

    updateConnectionStatus("Переподключение через 5 сек...");
    reconnectTimeout = setTimeout(() => {
        reconnectTimeout = null;
        connect();
    }, CONFIG.RECONNECT_DELAY);
}

function sendAuth() {
    const authMessage = {
        type: "auth",
        token: CONFIG.AUTH_TOKEN
    };

    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(authMessage));
    }
}

function sendMessage(text) {
    const message = {
        type: "message",
        data: text,
        timestamp: new Date().toISOString()
    };

    if (ws && ws.readyState === WebSocket.OPEN && isAuthenticated) {
        ws.send(JSON.stringify(message));
        addMessage("Вы", text, new Date(), true);
        return true;
    }
    return false;
}

function sendPing() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        const pingMessage = { type: "ping" };
        ws.send(JSON.stringify(pingMessage));

        // Визуальная индикация пинга
        pingDot.classList.add('active');
        setTimeout(() => {
            pingDot.classList.remove('active');
        }, 200);
    }
}

// === ОБРАБОТКА СООБЩЕНИЙ ===
function handleMessage(response) {
    switch (response.type) {
        case "auth":
            console.log("Получен ответ авторизации:", response);

            if (response.message === "AUTH_RESPONSE") {
                console.log("Успешная авторизация");
                isAuthenticated = true;
                updateStatusIndicators();
                updateConnectionStatus("Подключён и авторизован");
                enableInput();
                addSystemMessage("Авторизация успешна");
            }
            else {
                console.log("Авторизация не удалась");
                addSystemMessage("Ошибка авторизации");
            }
            break;

        case "message":
            console.log("Получено сообщение:", response.data);
            addMessage("Сервер", response.data, new Date(response.timestamp));
            break;

        case "pong":
            console.log("🏓 Pong получен");
            break;

        case "error":
            console.error("❌ Ошибка сервера:", response.message);
            addSystemMessage("Ошибка: " + response.message);
            break;

        default:
            console.warn("Неизвестный тип сообщения:", response.type);
    }
}

// === UI УПРАВЛЕНИЕ ===
function updateStatusIndicators() {
    // Соединение
    connectionDot.className = 'indicator-dot';
    if (isConnected) {
        connectionDot.classList.add('connected');
    }

    // Авторизация
    authDot.className = 'indicator-dot';
    if (isAuthenticated) {
        authDot.classList.add('connected');
    } else if (isConnected) {
        authDot.classList.add('warning');
    }

    // Ping (всегда активен при подключении)
    pingDot.className = 'indicator-dot';
    if (isConnected) {
        pingDot.classList.add('connected');
    }
}

function updateConnectionStatus(status) {
    connectionStatus.textContent = status;
}

function enableInput() {
    messageInput.disabled = false;
    sendBtn.disabled = false;
    messageInput.focus();
}

function disableInput() {
    messageInput.disabled = true;
    sendBtn.disabled = true;
}

function addMessage(sender, text, timestamp = new Date(), isOwn = false) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isOwn ? 'own' : ''}`;

    messageDiv.innerHTML = `
        <div class="message-header">
            <span class="message-author">${escapeHtml(sender)}</span>
            <span class="message-time">${formatTime(timestamp)}</span>
        </div>
        <div class="message-content">${escapeHtml(text)}</div>
    `;

    messagesList.appendChild(messageDiv);
    messagesList.scrollTop = messagesList.scrollHeight;
}

function addSystemMessage(text) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message system';

    messageDiv.innerHTML = `
        <div class="message-header">
            <span class="message-author">Система</span>
            <span class="message-time">${formatTime(new Date())}</span>
        </div>
        <div class="message-content">${escapeHtml(text)}</div>
    `;

    messagesList.appendChild(messageDiv);
    messagesList.scrollTop = messagesList.scrollHeight;
}

// === PING СИСТЕМА ===
function startPing() {
    if (pingInterval) stopPing();
    pingInterval = setInterval(sendPing, CONFIG.PING_INTERVAL);
}

function stopPing() {
    if (pingInterval) {
        clearInterval(pingInterval);
        pingInterval = null;
    }
}

// === EVENT LISTENERS ===
function setupEventListeners() {
    // Отправка сообщения
    sendBtn.addEventListener('click', function () {
        const text = messageInput.value.trim();
        if (text && sendMessage(text)) {
            messageInput.value = '';
        }
    });

    // Enter для отправки
    messageInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendBtn.click();
        }
    });

    // Закрытие при выходе со страницы
    window.addEventListener('beforeunload', function () {
        disconnect();
    });
}

// === ИНИЦИАЛИЗАЦИЯ ===
document.addEventListener('DOMContentLoaded', function () {
    // Получение элементов DOM
    messagesList = document.getElementById('chat-messages');
    messageInput = document.getElementById('message-input');
    sendBtn = document.getElementById('send-btn');
    connectionStatus = document.getElementById('connection-status');
    connectionDot = document.getElementById('connection-dot');
    authDot = document.getElementById('auth-dot');
    pingDot = document.getElementById('ping-dot');

    // Настройка обработчиков
    setupEventListeners();

    // Инициализация состояния
    updateStatusIndicators();
    disableInput();

    // Автоматическое подключение
    addSystemMessage("Инициализация подключения...");
    setTimeout(connect, 500);
});