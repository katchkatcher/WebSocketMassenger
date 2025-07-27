#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
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

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using error_code = boost::system::error_code;

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
        if(!logfile.is_open()) return;

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
    Logger() : logfile("server.log", std::ios::app) {
        if(!logfile.is_open())
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
        if(logfile.is_open())
        {
            log("=== 🛑 СЕРВЕР ОСТАНОВЛЕН ===", INFO);
            logfile.close();
        }
    }

    // Улучшенный формат времени
    std::string make_timestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        oss << "." << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

    std::string logTypeToString(LogType type)
    {
        switch (type)
        {
        case INFO:    return "INFO ";
        case ERRORS:  return "ERROR";
        case WARNINGS:return "WARN ";
        case DEBUG:   return "DEBUG";
        default:      return "UNKNW";
        }
    }

    // Базовые методы логирования
    void info(const std::string &msg) { log(msg, INFO); }
    void debug(const std::string &msg) { log(msg, DEBUG); }
    void error(const std::string &msg) { log(msg, ERRORS); }
    void warning(const std::string &msg) { log(msg, WARNINGS); }

    // Логирование ошибок с кодами
    void errorCode(boost::system::error_code ec, const char* what)
    {
        log("❌ " + std::string(what) + ": " + ec.message() + " (код: " + std::to_string(ec.value()) + ")", ERRORS);
    }

    // Специализированные методы для сессий
    void sessionInfo(int session_id, const std::string& msg) {
        log("👤 [S" + std::to_string(session_id) + "] " + msg, INFO);
    }
    
    void sessionDebug(int session_id, const std::string& msg) {
        log("🔧 [S" + std::to_string(session_id) + "] " + msg, DEBUG);
    }
    
    void sessionWarning(int session_id, const std::string& msg) {
        log("⚠️  [S" + std::to_string(session_id) + "] " + msg, WARNINGS);
    }

    void sessionError(int session_id, const std::string& msg) {
        log("❌ [S" + std::to_string(session_id) + "] " + msg, ERRORS);
    }

    // Логирование сетевых событий
    void serverEvent(const std::string& msg) {
        log("🌐 " + msg, INFO);
    }

    void connectionEvent(const std::string& msg) {
        log("🔌 " + msg, INFO);
    }

    // Логирование сообщений
    void messageEvent(int session_id, const std::string& direction, const std::string& msg) {
        std::string icon = (direction == "IN") ? "📥" : "📤";
        log(icon + " [S" + std::to_string(session_id) + "] " + direction + ": " + msg, DEBUG);
    }
};

Logger global_logger;

// обратное эхо вебсокет сообщений(подключение, рукопожатие, взаимодействие)
class session : public std::enable_shared_from_this<session>
{
    websocket::stream<beast::tcp_stream> ws_;          // основной поток websocket соедниения
    beast::flat_buffer buffer_;                        // буфер для сообщений от клиента
    const std::string valid_token_ = "Bearer mytoken"; // токен авторизации клиента
    bool authenticated_ = false;                       // флаг аутентификации текущего клиента
    static std::atomic<int> next_session_id;           // статический счетчик
    int session_id_;                                   // ID этой сессии
    std::string last_sent_message_;                    // Последнее отправленное сообщение
    
public:
    explicit session(tcp::socket &&socket)
        :   ws_(std::move(socket)),
            session_id_(++next_session_id) {}

    void run()
    {
        // организатор выполнения on_run в правильном потоке где находится исполнитель ws_ executor()
        net::dispatch(ws_.get_executor(),
                      beast::bind_front_handler(
                          &session::on_run,
                          shared_from_this()));
    }

private:
    void on_run()
    {
        // получаем сокет и устанавливаем таймаут в течение которого в случае бездействия клиента соединение закроется
        // get_lowest_layer - чистое TCP соединение без websocket обёртки
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // установка таймаута на websocket протокол(ping/pong)
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
            global_logger.sessionError(session_id_, "Ошибка при принятии соединения: " + ec.message());
            return;
        }
        
        global_logger.connectionEvent("Новый клиент подключен [S" + std::to_string(session_id_) + "]");
        do_read();
    }

    void on_close(error_code ec)
    {
        if (ec)
            global_logger.sessionError(session_id_, "Ошибка при закрытии: " + ec.message());

        global_logger.connectionEvent("Клиент отключился [S" + std::to_string(session_id_) + "]");
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
            global_logger.sessionInfo(session_id_, "WebSocket соединение закрыто клиентом");
            return;
        }

        if (ec)
        {
            global_logger.sessionError(session_id_, "Ошибка чтения: " + ec.message());
            return;
        }

        auto message = beast::buffers_to_string(buffer_.data());
        global_logger.messageEvent(session_id_, "IN", message);
        
        if (!authenticated_)
        {
            if (message.find(valid_token_) != std::string::npos)
            {
                authenticated_ = true;
                global_logger.sessionInfo(session_id_, "✅ Клиент успешно авторизован");
                
                std::string auth_response = "AUTH_SUCCESS";
                last_sent_message_ = auth_response;
                
                ws_.text(true);
                ws_.async_write(
                    net::buffer(auth_response),
                    beast::bind_front_handler(
                        &session::on_write,
                        shared_from_this()));
                return; // ⚠️ ВАЖНО: выходим, не обрабатываем как обычное сообщение
            } 
            else
            {
                global_logger.sessionWarning(session_id_, "🔐 Неверный токен авторизации");
                
                // Закрываем соединение при неверном токене
                ws_.async_close(websocket::close_code::policy_error,
                    beast::bind_front_handler(
                        &session::on_close,
                        shared_from_this()));
                return;
            }
        }

        if (authenticated_)
        {
            std::string custom_message = "Echo: " + message + " [Server Response]";
            last_sent_message_ = custom_message;

            ws_.text(ws_.got_text());
            ws_.async_write(
                net::buffer(custom_message),
                beast::bind_front_handler(
                    &session::on_write,
                    shared_from_this()));
        }
    }

    void on_write(error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec)
        {
            global_logger.sessionError(session_id_, "Ошибка отправки: " + ec.message());
            return;
        }

        // ИСПРАВЛЕНИЕ: Логируем отправленное сообщение
        global_logger.messageEvent(session_id_, "OUT", last_sent_message_);

        // очистка буфера
        buffer_.consume(buffer_.size());
        // читаем следующее сообщение
        do_read();
    }
};

std::atomic<int> session::next_session_id{0};

// слушает подключения
class listener : public std::enable_shared_from_this<listener>
{
    net::io_context &ioc_;
    tcp::acceptor acceptor_;

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

        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec)
        {
            global_logger.errorCode(ec, "Установка опций acceptor");
            return;
        }

        acceptor_.bind(endpoint, ec);
        if (ec)
        {
            global_logger.errorCode(ec, "Привязка acceptor к адресу");
            return;
        }

        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec)
        {
            global_logger.errorCode(ec, "Запуск прослушивания acceptor");
            return;
        }

        global_logger.serverEvent("Acceptor настроен и готов к приему соединений");
    }

    void run()
    {
        do_accept();
    }

private:
    void do_accept()
    {
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
            // Получаем информацию о клиенте
            auto remote_endpoint = socket.remote_endpoint();
            global_logger.connectionEvent("Новое TCP соединение от " + 
                remote_endpoint.address().to_string() + ":" + 
                std::to_string(remote_endpoint.port()));
                
            std::make_shared<session>(std::move(socket))->run();
        }

        do_accept();
    }
};

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

    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const threads = std::max<int>(1, std::atoi(argv[3]));

    net::io_context ioc{threads};

    global_logger.serverEvent("🚀 Запуск WebSocket сервера");
    global_logger.info("📍 Адрес: " + address.to_string() + ":" + std::to_string(port));
    global_logger.info("🧵 Потоков: " + std::to_string(threads));

    std::make_shared<listener>(ioc, tcp::endpoint{address, port})->run();

    global_logger.serverEvent("👂 Сервер готов к приему соединений");

    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
    {
        v.emplace_back([&ioc]
                       { 
                           global_logger.info("🔄 Рабочий поток запущен");
                           ioc.run(); 
                       });
    }
    ioc.run();

    return EXIT_SUCCESS;
}