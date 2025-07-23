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

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using error_code = boost::system::error_code;

// логирование ошибок в файл
void fail(boost::system::error_code ec, const char *what)
{
    std::ofstream log("server.log", std::ios::app);
    log << what << ": " << ec.message() << "\n";
    std::cerr << what << ": " << ec.message() << "\n";
}

// обратное эхо вебсокет сообщений(подключение, рукопожатие, взаимодействие)
class session : public std::enable_shared_from_this<session>
{
    websocket::stream<beast::tcp_stream> ws_;           // основной поток websocket соедниения
    beast::flat_buffer buffer_;                         // буфер для сообщений от клиента
    const std::string valid_token_ = "Bearer mytoken";  // токен авторизации клиента
    bool authenticated_ = false;                        // флаг аутентификации текущего клиента

public:
    explicit session(tcp::socket &&socket)
        : ws_(std::move(socket)) {}

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
            return fail(ec, "accept");

        // Отключаем таймаут для долгоживущего WebSocket
        // т.к при таймауте если пользователь сообщение не читает, соединение оффается
        beast::get_lowest_layer(ws_).expires_never();
 
        std::cout << "👤 Новый клиент подключен" << std::endl;

        do_read();
    }

    void on_close(error_code ec)
    {
        if (ec)
            fail(ec, "close");

        std::cout << "👋 Клиент отключился" << std::endl;
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
        // игнорируем пустой неиспользуемый параметр в callback функции
        boost::ignore_unused(bytes_transferred);

        if (ec == websocket::error::closed)
        {
            std::cout << "📴 WebSocket закрыт клиентом" << std::endl;
            return;
        }

        if (ec)
            return fail(ec, "read");

        // получаем сообщение от клиента
        auto message = beast::buffers_to_string(buffer_.data());
        
        std::cout << "📩 Получено: " << message << std::endl;

        if (!authenticated_)
        {
            // ищем токен авторизации
            if (message.find(valid_token_) != std::string::npos)
            {
                authenticated_ = true;
                std::cout << "🔑 Клиент авторизован" << std::endl;
                
                std::string auth_response = "AUTH_SUCCESS";
                ws_.text(true);
                ws_.async_write(
                    net::buffer(auth_response),
                    beast::bind_front_handler(
                        &session::on_write,
                        shared_from_this()));
                return;
            }
            else
            {
                std::cout << "⛔ Неверный токен, закрываем соединение" << std::endl;
                ws_.async_close(websocket::close_code::normal,
                                beast::bind_front_handler(
                                    &session::on_close,
                                    shared_from_this()));
                return;
            }
        }

        std::string custom_message = "Сразу видно что темя не работае \n Тупаръё просто и всё";

        // отправляем кастомное сообщение
        ws_.text(ws_.got_text());
        ws_.async_write(
            net::buffer(custom_message),
            beast::bind_front_handler(
                &session::on_write,
                shared_from_this()));
    }

    void on_write(error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "write");

        std::cout << "📤 Отправлено: " << beast::buffers_to_string(buffer_.data()) << std::endl;

        // очистка буфера
        buffer_.consume(buffer_.size());
        // читаем следующее сообщение
        do_read();
    }
};

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
            fail(ec, "open");
            return;
        }

        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec)
        {
            fail(ec, "set_option");
            return;
        }

        acceptor_.bind(endpoint, ec);
        if (ec)
        {
            fail(ec, "bind");
            return;
        }

        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec)
        {
            fail(ec, "listen");
            return;
        }
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
            fail(ec, "accept");
        }
        else
        {
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

    std::cout << "🚀 Сервер запускается на " << address << ":" << port << std::endl;
    std::cout << "⚠️ Режим разработки: SSL отключен" << std::endl;

    std::make_shared<listener>(ioc, tcp::endpoint{address, port})->run();

    std::cout << "👂 Сервер слушает подключения..." << std::endl;

    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
    {
        v.emplace_back([&ioc] { ioc.run(); });
    }
    ioc.run();

    return EXIT_SUCCESS;
}