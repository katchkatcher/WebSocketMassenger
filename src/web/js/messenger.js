// === ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ===
let ws = null;
let isConnected = false;
let isAuthenticated = false;
let pingInterval = null;
let reconnectTimeout = null;
let currentUsername = "";

// === ЭЛЕМЕНТЫ DOM ===
let messagesList, messageInput, sendBtn, connectionStatus;
let connectionDot, authDot, pingDot;
let usernameModal = null;
let usernameInput = null;
let joinBtn = null;
let authError = null;
let usersListEl = null;
let usersCountEl = null;

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

function setUsers(users) {
    usersListEl.innerHTML = '';
    users.forEach(u => {
        const item = document.createElement('div');
        item.className = 'user-item';
        item.textContent = u;
        usersListEl.appendChild(item);
    });
    usersCountEl.textContent = users.length;
}

function addUser(u) {
    const exists = Array.from(usersListEl.children).some(el => el.textContent === u);
    if (!exists) {
        const item = document.createElement('div');
        item.className = 'user-item';
        item.textContent = u;
        usersListEl.appendChild(item);
        usersCountEl.textContent = String(Number(usersCountEl.textContent) + 1);
    }
}

function removeUser(u) {
    const child = Array.from(usersListEl.children).find(el => el.textContent === u);
    if (child) {
        usersListEl.removeChild(child);
        usersCountEl.textContent = String(Math.max(0, Number(usersCountEl.textContent) - 1));
    }
}

// === WEBSOCKET ЛОГИКА ===
function connect() {
    updateConnectionStatus("Подключение...");

    try {
        ws = new WebSocket(CONFIG.WS_URL);

        ws.onopen = function () {
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
        token: CONFIG.AUTH_TOKEN, 
        username: currentUsername
    };

    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(authMessage));
    }
}

function sendMessage(text) {
    const message = {
        type: "broadcast",
        message: text,
        timestamp: new Date().toISOString()
    };

    if (ws && ws.readyState === WebSocket.OPEN && isAuthenticated) {
        ws.send(JSON.stringify(message));
        addMessage(currentUsername, text, new Date(), true); 
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
            if (response.message === "AUTH_RESPONSE") {
                isAuthenticated = true;
                updateStatusIndicators();
                updateConnectionStatus("Подключён и авторизован");
                enableInput();
                addSystemMessage("Авторизация успешна");
            } else {
                addSystemMessage("Ошибка авторизации");
            }
            break;

        case "user_list":
            if (Array.isArray(response.users)) {
                setUsers(response.users);
            }
            break;

        case "user_joined":
            addSystemMessage(`${response.username} присоединился к чату`);
            addUser(response.username);
            break;

        case "user_left":
            addSystemMessage(`${response.username} покинул чат`);
            removeUser(response.username);
            break;

        case "message":
            addMessage(response.from || "Сервер", response.data, new Date(response.timestamp));
            break;

        case "broadcast":
            addMessage(response.from, response.message, new Date(response.timestamp), false);
            break;

        case "pong":
            // no-op; индикатор уже мигает при отправке
            break;

        case "error":
        case "auth_error":
            showUsernameModal();
            showAuthError(response.message || "Ошибка");
            isAuthenticated = false;
            updateStatusIndicators();
            updateConnectionStatus("Ошибка авторизации");
            break;

        default:
            console.warn("Неизвестный тип сообщения:", response.type);
    }
}

// === UI УПРАВЛЕНИЕ ===
function updateStatusIndicators() {
    connectionDot.className = 'indicator-dot';
    if (isConnected) connectionDot.classList.add('connected');

    authDot.className = 'indicator-dot';
    if (isAuthenticated) authDot.classList.add('connected');
    else if (isConnected) authDot.classList.add('warning');

    pingDot.className = 'indicator-dot';
    if (isConnected) pingDot.classList.add('connected');
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



function isScrolledToBottom() {
    const threshold = 50; 
    return messagesList.scrollTop >= (messagesList.scrollHeight - messagesList.clientHeight - threshold);
}

function scrollToBottom() {
    messagesList.scrollTop = messagesList.scrollHeight;
}

function smartScrollToBottom() {
    if (isScrolledToBottom()) {
        requestAnimationFrame(() => {
            scrollToBottom();
        });
    }
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

    if (isOwn) {
        scrollToBottom();
    } else {
        smartScrollToBottom();
    }
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
    
    smartScrollToBottom();
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
    sendBtn.addEventListener('click', function () {
        const text = messageInput.value.trim();
        if (text && sendMessage(text)) {
            messageInput.value = '';
        }
    });

    messageInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendBtn.click();
        }
    });

    messagesList.addEventListener('dblclick', function() {
        scrollToBottom();
    });

    window.addEventListener('beforeunload', function () {
        disconnect();
    });

    joinBtn.addEventListener('click', handleUsernameSubmit);
    usernameInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            handleUsernameSubmit();
        }
    });
}

// === МОДАЛЬНОЕ ОКНО ===
function showUsernameModal() {
    usernameModal.style.display = 'flex';
    usernameInput.focus();
}

function hideUsernameModal() {
    usernameModal.style.display = 'none';
}

function showAuthError(message) {
    authError.textContent = message;
    authError.style.display = 'block';
}

function hideAuthError() {
    authError.style.display = 'none';
}

function handleUsernameSubmit() {
    const username = usernameInput.value.trim();
    if (!username) {
        showAuthError("Пожалуйста, введите ваше имя");
        return;
    }
    if (username.length > 20) {
        showAuthError("Имя слишком длинное (максимум 20 символов)");
        return;
    }

    currentUsername = username;
    hideAuthError();
    hideUsernameModal();
    updateConnectionStatus("Подключение...");
    connect();
}

// === ИНИЦИАЛИЗАЦИЯ ===
document.addEventListener('DOMContentLoaded', function () {
    messagesList = document.getElementById('chat-messages');
    messageInput = document.getElementById('message-input');
    sendBtn = document.getElementById('send-btn');
    connectionStatus = document.getElementById('connection-status');
    connectionDot = document.getElementById('connection-dot');
    authDot = document.getElementById('auth-dot');
    pingDot = document.getElementById('ping-dot');
    usernameModal = document.getElementById('username-modal');
    usernameInput = document.getElementById('username-input');
    joinBtn = document.getElementById('join-btn');
    authError = document.getElementById('auth-error');
    usersListEl = document.getElementById('users-list');
    usersCountEl = document.getElementById('users-count');

    setupEventListeners();
    updateStatusIndicators();
    disableInput();
    showUsernameModal();
});
