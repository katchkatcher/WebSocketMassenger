#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <cstdio>
#include <signal.h>
#include <chrono>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif
#include <deque>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using error_code = boost::system::error_code;
using json = nlohmann::json;

enum LogType
{
    INFO,
    ERRORS,
    WARNINGS,
    DEBUG
};

class Logger
{
private:
    std::mutex log_locker;
    std::ofstream logfile;

    void log(const std::string &message, LogType type)
    {
        if (!logfile.is_open())
            return;

        std::lock_guard<std::mutex> guard(log_locker);
        std::string timestamp = make_timestamp();

        if (!timestamp.empty())
        {
            auto thread_id = std::this_thread::get_id();
            std::ostringstream thread_stream;
            thread_stream << thread_id;

            logfile << "[" << timestamp << "] "
                    << "[TH-" << thread_stream.str().substr(0, 6) << "] "
                    << "[" << logTypeToString(type) << "] "
                    << message << std::endl;
            logfile.flush();
        }
    }

public:
    Logger() : logfile("server.log", std::ios::out | std::ios::trunc)
    {
        if (!logfile.is_open())
        {
            std::cerr << "❌ Не удалось открыть лог файл!" << std::endl;
        }
        else
        {
            // Запись старта сессии логирования
            log("=== 🚀 СЕРВЕР ЗАПУЩЕН ===", INFO);
        }
    }

    ~Logger()
    {
        if (logfile.is_open())
        {
            log("=== 🛑 СЕРВЕР ОСТАНОВЛЕН ===", INFO);
            logfile.close();
        }
    }

    std::string make_timestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &time_t);
#else
        localtime_r(&time_t, &tm);
#endif

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) %
                  1000;

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        oss << "." << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

    std::string logTypeToString(LogType type)
    {
        switch (type)
        {
        case INFO:
            return "INFO ";
        case ERRORS:
            return "ERROR";
        case WARNINGS:
            return "WARN ";
        case DEBUG:
            return "DEBUG";
        default:
            return "UNKNW";
        }
    }

    // Базовые методы логирования
    void info(const std::string &msg) { log(msg, INFO); }
    void debug(const std::string &msg) { log(msg, DEBUG); }
    void error(const std::string &msg) { log(msg, ERRORS); }
    void warning(const std::string &msg) { log(msg, WARNINGS); }

    // Логирование ошибок с кодами
    void errorCode(boost::system::error_code ec, const char *what)
    {
        log("❌ " + std::string(what) + ": " + ec.message() + " (код: " + std::to_string(ec.value()) + ")", ERRORS);
    }

    // Специализированные методы для сессий
    void sessionInfo(int session_id, const std::string &msg)
    {
        log("👤 [S" + std::to_string(session_id) + "] " + msg, INFO);
    }

    void sessionDebug(int session_id, const std::string &msg)
    {
        log("🔧 [S" + std::to_string(session_id) + "] " + msg, DEBUG);
    }

    void sessionWarning(int session_id, const std::string &msg)
    {
        log("⚠️  [S" + std::to_string(session_id) + "] " + msg, WARNINGS);
    }

    void sessionError(int session_id, const std::string &msg)
    {
        log("❌ [S" + std::to_string(session_id) + "] " + msg, ERRORS);
    }

    // Логирование сетевых событий
    void serverEvent(const std::string &msg)
    {
        log("🌐 " + msg, INFO);
    }

    void connectionEvent(const std::string &msg)
    {
        log("🔌 " + msg, INFO);
    }

    // Логирование сообщений
    void messageEvent(int session_id, const std::string &direction, const std::string &msg)
    {
        std::string icon = (direction == "IN") ? "📥" : "📤";
        log(icon + " [S" + std::to_string(session_id) + "] " + direction + ": " + msg, DEBUG);
    }
};

Logger global_logger;

class session;

class SessionManager
{
    std::unordered_map<int, std::shared_ptr<session>> sessions_;
    std::unordered_set<std::string> used_usernames_;
    std::unordered_map<int, std::string> session_to_username_;
    std::mutex mutex_;

public:
    void add_session(int id, const std::string &username, std::shared_ptr<session> session); // добавлениие пользовательской сессии
    void remove_session(int id);                                                             // удаление пользовательской сессии
    void broadcast_message(const json &message, int sender_id = -1);                         // отправка всем пользователям
    size_t get_user_count();                                                                 // количество онлайн пользователей
    bool is_surname_taken(const std::string &username);                                      // проверка на то не занятое ли имя
    void add_username(const std::string &username);                                          // добавление имени пользователя в список используемых
    std::vector<std::string> get_user_list();                                                // получение списка пользователей
};

SessionManager global_session_manager;

class session : public std::enable_shared_from_this<session>
{
    std::string username_;
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    const std::string valid_token_ = "Bearer mytoken";
    bool authenticated_ = false;
    static std::atomic<int> next_session_id;
    static std::atomic<int> temp_connection_id;
    int session_id_ = -1; // Реальный ID сессии (-1 = не авторизован)
    int connection_id_;   // Временный ID для логирования
    std::string last_sent_message_;
    std::atomic<bool> removed_ = false;

    // Очередь исходящих сообщений (сериализованная запись)
    std::deque<std::string> write_queue_;

public:
    explicit session(tcp::socket &&socket)
        : ws_(std::move(socket)),
          connection_id_(++temp_connection_id)
    {
    }

    ~session()
    {
        if (session_id_ > 0)
        {
            global_logger.sessionInfo(session_id_, "Деструктор сессии");
        }
    }

    void run()
    {
        // организатор выполнения on_run в правильном потоке где находится исполнитель ws_ executor()
        net::dispatch(ws_.get_executor(),
                      beast::bind_front_handler(
                          &session::on_run,
                          shared_from_this()));
    }

    void send_message(const json &message)
    {
        auto self = shared_from_this();
        std::string payload = message.dump();
        last_sent_message_ = payload;

        // self - сессия
        // payload - сообщение для отправки
        net::post(ws_.get_executor(), [self, payload]()
                  {
            if (!self->ws_.is_open())
            {
                global_logger.sessionWarning(self->session_id_, "Попытка отправки в закрытое соединение");
                return;
            }
            // флаг пустая ли очередь
            bool idle = self->write_queue_.empty();
            // сообщение в конец очереди
            self->write_queue_.push_back(payload);
            // если пустая отправляем
            if (idle)
            {
                self->do_write();
            } });
    }

private:
    void do_write()
    {
        if (write_queue_.empty())
            return;
        ws_.text(true);
        ws_.async_write(
            net::buffer(write_queue_.front()),
            beast::bind_front_handler(&session::on_write_queue, shared_from_this()));
    }

    void on_write_queue(error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);
        if (ec)
        {
            if (session_id_ > 0)
            {
                global_logger.sessionError(session_id_, "Ошибка отправки: " + ec.message());
            }
            else
            {
                global_logger.error("❌ [C" + std::to_string(connection_id_) + "] Ошибка отправки: " + ec.message());
            }
            // В случае ошибки закрываем соединение
            ws_.async_close(websocket::close_code::normal,
                            beast::bind_front_handler(&session::on_close, shared_from_this()));
            return;
        }

        if (session_id_ > 0)
        {
            global_logger.messageEvent(session_id_, "OUT", write_queue_.front());
        }
        // очищаем в очередь
        write_queue_.pop_front();
        if (!write_queue_.empty())
        {
            do_write();
        }
    }

    void on_run()
    {
        // получаем сокет и устанавливаем таймаут в течение которого в случае бездействия клиента соединение закроется
        // get_lowest_layer - чистое TCP соединение без websocket обёртки
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(120));

        // установка таймаута на websocket протокол, рекомендованные значения
        ws_.set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::server));

        // HTTP заголовок чтобы установить WebSocket соединение
        ws_.set_option(websocket::stream_base::decorator(
            [](websocket::response_type &res)
            {
                res.set(http::field::server,
                        std::string(BOOST_BEAST_VERSION_STRING) +
                            " websocket-server-async");
            }));

        ws_.async_accept(
            beast::bind_front_handler(
                &session::on_accept,
                shared_from_this()));
    }

    void on_accept(error_code ec)
    {
        if (ec)
        {
            global_logger.error("❌ [C" + std::to_string(connection_id_) + "] Ошибка при принятии соединения: " + ec.message());
            return;
        }

        do_read();
    }

    void on_close(error_code ec)
    {
        if (ec)
        {
            if (session_id_ > 0)
            {
                global_logger.sessionError(session_id_, "Ошибка при закрытии: " + ec.message());
            }
        }

        safe_remove_session();

        if (session_id_ > 0)
        {
            global_logger.connectionEvent("Клиент отключился [S" + std::to_string(session_id_) + "]");
        }
    }

    void do_read()
    {
        ws_.async_read(
            buffer_,
            beast::bind_front_handler(
                &session::on_read,
                shared_from_this()));
    }

    void on_read(error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec == websocket::error::closed)
        {
            if (session_id_ > 0)
            {
                global_session_manager.remove_session(session_id_);
                global_logger.sessionInfo(session_id_, "WebSocket соединение закрыто клиентом");
            }
            return;
        }

        if (ec)
        {
            if (session_id_ > 0)
            {
                global_session_manager.remove_session(session_id_);
                global_logger.sessionError(session_id_, "Ошибка чтения: " + ec.message());
            }
            return;
        }

        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(120));

        auto message = beast::buffers_to_string(buffer_.data());
        buffer_.consume(buffer_.size());

        if (session_id_ > 0)
        {
            global_logger.messageEvent(session_id_, "IN", message);
        }

        bool should_continue_read = true;

        try
        {
            json parsed = json::parse(message);
            std::string type;
            if (parsed.contains("type") && parsed["type"].is_string())
            {
                type = parsed["type"];
                if (type == "auth")
                {
                    handle_auth_message(parsed);
                }
                else if (type == "message")
                {
                    if (!authenticated_)
                    {
                        global_logger.sessionWarning(session_id_, "🔐 Попытка отправки сообщения без авторизации");
                    }
                    else if (parsed.contains("data"))
                    {
                        std::string msg_data = parsed["data"];
                        json broadcast_message = {{"type", "message"},
                                                  {"data", msg_data},
                                                  {"sender_id", session_id_},
                                                  {"from", username_},
                                                  {"timestamp", global_logger.make_timestamp()}};
                        global_session_manager.broadcast_message(broadcast_message, session_id_);
                        global_logger.sessionInfo(session_id_, "Сообщение отправлено всем клиентам: " + msg_data);
                    }
                }
                else if (type == "ping")
                {
                    json pong_response = {{"type", "pong"}, {"timestamp", global_logger.make_timestamp()}};
                    send_message(pong_response);
                }
                else if (type == "broadcast")
                {
                    if (!authenticated_)
                    {
                        global_logger.sessionWarning(session_id_, "🔐 Попытка broadcast без авторизации");
                    }
                    else if (parsed.contains("message"))
                    {
                        std::string msg_data = parsed["message"];
                        json broadcast_message = {{"type", "broadcast"},
                                                  {"from", username_},
                                                  {"message", msg_data},
                                                  {"timestamp", global_logger.make_timestamp()}};
                        global_session_manager.broadcast_message(broadcast_message, session_id_);
                        global_logger.sessionInfo(session_id_, "Broadcast сообщение от " + username_ + ": " + msg_data);
                    }
                }
                else
                {
                    global_logger.sessionWarning(session_id_, "🚫 Неизвестный тип сообщения: " + type);
                    json error_response = {{"type", "error"}, {"message", "Unknown message type: " + type}};
                    send_message(error_response);
                }
            }
            else
            {
                global_logger.sessionWarning(session_id_, "🚫 Отсутствует поле 'type' или оно не строка");
            }
        }
        catch (json::parse_error &e)
        {
            global_logger.sessionWarning(session_id_, "🚫 Некорректный JSON: " + std::string(e.what()));
        }

        if (should_continue_read)
            do_read();
    }

    void handle_auth_message(const json &parsed)
    {
        if (!parsed.contains("token") || !parsed.contains("username"))
        {
            global_logger.warning("🔐 [C" + std::to_string(connection_id_) + "] Отсутствуют поля token или username");
            return;
        }
        std::string token = parsed["token"];
        std::string username = parsed["username"];

        if (token != valid_token_)
        {
            global_logger.warning("🔐 [C" + std::to_string(connection_id_) + "] Неверный токен авторизации");
            ws_.async_close(websocket::close_code::policy_error,
                            beast::bind_front_handler(&session::on_close, shared_from_this()));
            return;
        }

        if (username.empty())
        {
            json empty_name = {
                {"type", "auth_error"},
                {"message", "Пустое имя"}};
            send_message(empty_name);
            global_logger.warning("🔐 [C" + std::to_string(connection_id_) + "] Введена пустая строка");
            return;
        }

        if (global_session_manager.is_surname_taken(username))
        {
            json name_taken = {
                {"type", "auth_error"},
                {"message", "Имя уже занято. Введите другое"}};
            send_message(name_taken);

            global_logger.info("🚫 Авторизация отклонена - имя занято: " + username);

            ws_.async_close(websocket::close_code::policy_error,
                            beast::bind_front_handler(&session::on_close, shared_from_this()));
            return;
        }

        session_id_ = ++next_session_id;
        username_ = username;
        authenticated_ = true;

        global_logger.connectionEvent("Новый клиент подключен [S" + std::to_string(session_id_) + "] как: " + username_);

        global_session_manager.add_session(session_id_, username_, shared_from_this());

        json auth_response = {
            {"type", "auth"},
            {"message", "AUTH_RESPONSE"}};
        send_message(auth_response);

        json user_list = {
            {"type", "user_list"},
            {"users", global_session_manager.get_user_list()}};
        send_message(user_list);

        json user_joined = {
            {"type", "user_joined"},
            {"username", username_}};
        global_session_manager.broadcast_message(user_joined, session_id_);
    }

    void safe_remove_session()
    {
        bool expected = false;
        // сравнивает и заменяет в случае если флаги равны. (expected)false -> true
        if (removed_.compare_exchange_strong(expected, true))
        {
            // удаление сессии
            global_session_manager.remove_session(session_id_);
        }
    }
};

std::atomic<int> session::next_session_id{0};
std::atomic<int> session::temp_connection_id{0};

void SessionManager::add_session(int id, const std::string &username, std::shared_ptr<session> session)
{
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_[id] = std::move(session);
    session_to_username_[id] = username;
    used_usernames_.insert(username);
    global_logger.info("👥 Пользователь добавлен: " + username + ". Всего: " + std::to_string(sessions_.size()));
}

void SessionManager::remove_session(int id)
{
    std::vector<std::shared_ptr<session>> targets;
    std::string username;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto itName = session_to_username_.find(id);
        if (itName != session_to_username_.end())
        {
            username = itName->second;
            used_usernames_.erase(username);
            session_to_username_.erase(itName);
            global_logger.info("👥 Освобождено имя: " + username);
        }

        // Скопируем получателей для нотификации user_left
        for (auto &[sid, sp] : sessions_)
        {
            if (sid != id && sp)
                targets.push_back(sp);
        }

        sessions_.erase(id);
    }

    // Уведомим остальных вне лока
    if (!username.empty())
    {
        json user_left = {{"type", "user_left"}, {"username", username}};
        for (auto &s : targets)
            s->send_message(user_left);
    }

    global_logger.info("👥 Пользователь отключился. Всего: " + std::to_string(get_user_count()));
}

void SessionManager::broadcast_message(const json &message, int sender_id)
{
    global_logger.debug("📡 Начало broadcast от сессии " + std::to_string(sender_id));
    std::vector<std::shared_ptr<session>> targets;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto &[id, sp] : sessions_)
        {
            if (id != sender_id && sp)
            {
                targets.push_back(sp);
                global_logger.debug("📡 Добавлен получатель: " + std::to_string(id));
            }
        }
    }

    global_logger.debug("📡 Отправка " + std::to_string(targets.size()) + " получателям");
    for (auto &s : targets)
        s->send_message(message);
    global_logger.debug("📡 Broadcast завершен");
}

size_t SessionManager::get_user_count()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

bool SessionManager::is_surname_taken(const std::string &username)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (username.empty())
        return true;
    return used_usernames_.find(username) != used_usernames_.end();
}

void SessionManager::add_username(const std::string &username)
{
    std::lock_guard<std::mutex> lock(mutex_);
    used_usernames_.insert(username);
}

std::vector<std::string> SessionManager::get_user_list()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> users;
    users.reserve(session_to_username_.size());
    for (auto &p : session_to_username_)
        users.push_back(p.second);
    std::sort(users.begin(), users.end());
    return users;
}

// слушает подключения
class listener : public std::enable_shared_from_this<listener>
{
    net::io_context &ioc_;
    tcp::acceptor acceptor_;
    bool ready_ = false; // флаг успешной инициализации

public:
    listener(net::io_context &ioc, tcp::endpoint endpoint)
        : ioc_(ioc),
          acceptor_(net::make_strand(ioc))
    {
        error_code ec;

        acceptor_.open(endpoint.protocol(), ec);
        if (ec)
        {
            global_logger.errorCode(ec, "Открытие acceptor");
            return;
        }

        // включаем REUSEADDR на всех платформах
        // мгновенное переиспользование адреса
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec)
        {
            global_logger.errorCode(ec, "Установка REUSEADDR");
            return;
        }

        // отключение Nagle для уменьшения задержки
        acceptor_.set_option(tcp::no_delay(true), ec);
        if (ec)
        {
            global_logger.errorCode(ec, "Установка no_delay");
            return;
        }

        // Привязка к адресу
        acceptor_.bind(endpoint, ec);
        if (ec)
        {
            global_logger.errorCode(ec, "Привязка acceptor к адресу");
            return;
        }

        // Запуск прослушивания
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec)
        {
            global_logger.errorCode(ec, "Запуск прослушивания acceptor");
            return;
        }

        ready_ = true;
        try
        {
            auto lep = acceptor_.local_endpoint();
            global_logger.serverEvent("Acceptor слушает на " + lep.address().to_string() + ":" + std::to_string(lep.port()));
        }
        catch (...)
        {
        }
        global_logger.serverEvent("Acceptor настроен и готов к приему соединений");
    }

    bool is_ready() const noexcept { return ready_ && acceptor_.is_open(); }

    void run()
    {
        if (!ready_ || !acceptor_.is_open())
        {
            global_logger.error("Acceptor не готов. Прослушивание не запущено.");
            return;
        }
        do_accept();
    }

private:
    void do_accept()
    {
        if (!acceptor_.is_open())
        {
            global_logger.error("Попытка принять соединение на закрытом acceptor");
            return;
        }
        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(
                &listener::on_accept,
                shared_from_this()));
    }

    void on_accept(error_code ec, tcp::socket socket)
    {
        if (ec)
        {
            global_logger.errorCode(ec, "Принятие соединения");
        }
        else
        {
            try
            {
                auto remote_endpoint = socket.remote_endpoint();
                global_logger.connectionEvent("Новое TCP соединение от " +
                                              remote_endpoint.address().to_string() + ":" +
                                              std::to_string(remote_endpoint.port()));
            }
            catch (const std::exception &ex)
            {
                global_logger.warning(std::string("Не удалось получить remote_endpoint: ") + ex.what());
            }

            // создаём объект сессии и запускаем
            std::make_shared<session>(std::move(socket))->run();
        }

        // Продолжаем принимать, только если acceptor всё ещё открыт
        if (acceptor_.is_open())
            do_accept();
    }
};

void signal_handler(int signal)
{
    global_logger.info("=== ПОЛУЧЕН СИГНАЛ ЗАВЕРШЕНИЯ ===");
    global_logger.info("Очистка ресурсов...");
    global_logger.info("Активных сессий: " + std::to_string(global_session_manager.get_user_count()));
    global_logger.info("=== СЕРВЕР ОСТАНОВЛЕН ===");
    exit(signal);
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (argc != 4)
    {
        std::cerr << "Usage: websocket-server-async <address> <port> <threads>\n"
                  << "Example:\n"
                  << "    websocket-server-async 0.0.0.0 8080 1\n";
        return EXIT_FAILURE;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const threads = std::max<int>(1, std::atoi(argv[3]));

    net::io_context ioc{threads};

    global_logger.serverEvent("🚀 Запуск WebSocket сервера");
    global_logger.info("📍 Адрес: " + address.to_string() + ":" + std::to_string(port));
    global_logger.info("🧵 Потоков: " + std::to_string(threads));

    auto lst = std::make_shared<listener>(ioc, tcp::endpoint{address, port});
    if (!lst->is_ready())
    {
        global_logger.error("Не удалось инициализировать acceptor. Завершение.");
        return EXIT_FAILURE;
    }
    lst->run();

    global_logger.serverEvent("👂 Сервер готов к приему соединений");

    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
    {
        v.emplace_back([&ioc]
                       { 
                           global_logger.info("🔄 Рабочий поток запущен");
                           ioc.run(); });
    }
    ioc.run();

    return EXIT_SUCCESS;
}