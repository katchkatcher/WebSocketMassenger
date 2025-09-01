#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/signal_set.hpp>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <atomic>
#include <deque>
#include <string_view>
#include "config.h"
#include "logger.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using error_code = boost::system::error_code;
using json = nlohmann::json;

// Forward declarations
class session;
class SessionManager;
class listener;

// Global objects with proper lifetime management
std::unique_ptr<Logger> g_logger;
std::unique_ptr<SessionManager> g_session_manager;
std::atomic<bool> g_shutdown_requested{false};

// Helper function to create timestamps
std::string make_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &time_t);
#else
    localtime_r(&time_t, &tm);
#endif

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

class SessionManager {
    std::unordered_map<int, std::shared_ptr<session>> sessions_;
    std::unordered_set<std::string> used_usernames_;
    std::unordered_map<int, std::string> session_to_username_;
    std::unordered_map<std::string, std::deque<json>> room_history_; // Message history per room
    mutable std::mutex mutex_;
    const Config& cfg_;
    std::atomic<bool> shutdown_initiated_{false};

public:
    explicit SessionManager(const Config& cfg) : cfg_(cfg) {
        // Initialize default room
        room_history_["global"] = std::deque<json>();
    }

    void add_session(int id, const std::string& username, std::shared_ptr<session> session);
    void remove_session(int id);
    void broadcast_message(const json& message, int sender_id = -1, const std::string& room = "global");
    void add_message_to_history(const json& message, const std::string& room = "global");
    std::vector<json> get_room_history(const std::string& room, size_t max_messages = 10) const;
    
    size_t get_user_count() const;
    bool is_username_taken(const std::string& username) const;
    std::vector<std::string> get_user_list() const;
    
    void shutdown_all();
    bool is_shutdown_initiated() const { return shutdown_initiated_.load(); }
    
    // Validation methods
    bool is_valid_username(const std::string& username) const;
    bool is_valid_room_name(const std::string& room) const;
};

class session : public std::enable_shared_from_this<session> {
    std::string username_;
    std::string current_room_ = "global";
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    bool authenticated_ = false;
    static std::atomic<int> next_session_id_;
    static std::atomic<int> temp_connection_id_;
    int session_id_ = -1;
    int connection_id_;
    
    const Config& cfg_;
    std::deque<std::string> write_queue_;
    std::atomic<bool> writing_{false};
    std::chrono::steady_clock::time_point last_msg_time_;
    size_t message_count_in_window_ = 0;
    std::chrono::steady_clock::time_point rate_limit_window_start_;
    std::atomic<bool> removed_{false};
    std::atomic<bool> closing_{false};

public:
    explicit session(tcp::socket&& socket, const Config& cfg)
        : ws_(std::move(socket)),
          connection_id_(++temp_connection_id_),
          cfg_(cfg),
          last_msg_time_(std::chrono::steady_clock::now()),
          rate_limit_window_start_(std::chrono::steady_clock::now()) {
    }

    ~session() {
        if (session_id_ > 0) {
            g_logger->sessionInfo(session_id_, "Session destructor");
        }
    }

    void run() {
        net::dispatch(ws_.get_executor(),
                      beast::bind_front_handler(&session::on_run, shared_from_this()));
    }

    void shutdown() {
        bool expected = false;
        if (!closing_.compare_exchange_strong(expected, true)) {
            return; // Already closing
        }

        g_logger->sessionInfo(session_id_, "Initiating graceful shutdown");
        
        // Clear write queue
        write_queue_.clear();
        
        if (ws_.is_open()) {
            ws_.async_close(websocket::close_code::going_away,
                            beast::bind_front_handler(&session::on_close, shared_from_this()));
        } else {
            safe_remove_session();
        }
    }

    void send_message(const json& message) {
        if (closing_.load() || g_shutdown_requested.load()) {
            return;
        }

        // Rate limiting check
        if (!check_rate_limit()) {
            g_logger->sessionWarning(session_id_, "Rate limit exceeded");
            json error_msg = {
                {"type", "error"},
                {"message", "Rate limit exceeded. Please slow down."}
            };
            queue_message(error_msg.dump());
            return;
        }

        queue_message(message.dump());
    }

    void send_room_history() {
        if (!authenticated_) return;
        
        auto history = g_session_manager->get_room_history(current_room_, 10);
        if (!history.empty()) {
            json history_msg = {
                {"type", "history"},
                {"room", current_room_},
                {"messages", history}
            };
            send_message(history_msg);
        }
    }

    const std::string& get_username() const { return username_; }
    int get_session_id() const { return session_id_; }

private:
    bool check_rate_limit() {
        auto now = std::chrono::steady_clock::now();
        
        // Reset window if needed
        if (now - rate_limit_window_start_ >= cfg_.rate_limit_window) {
            rate_limit_window_start_ = now;
            message_count_in_window_ = 0;
        }
        
        if (message_count_in_window_ >= cfg_.rate_limit_max_messages) {
            return false;
        }
        
        ++message_count_in_window_;
        return true;
    }

    void queue_message(std::string payload) {
        auto self = shared_from_this();
        net::post(ws_.get_executor(), [self, payload = std::move(payload)]() {
            if (self->closing_.load() || !self->ws_.is_open()) {
                return;
            }

            // Manage queue size
            if (self->write_queue_.size() >= self->cfg_.max_queue_size) {
                self->write_queue_.pop_front();
                g_logger->sessionWarning(self->session_id_, "Write queue full, dropping oldest message");
            }

            self->write_queue_.push_back(std::move(payload));
            
            // Start writing if not already writing
            bool expected = false;
            if (self->writing_.compare_exchange_strong(expected, true)) {
                self->do_write();
            }
        });
    }

    void do_write() {
        if (write_queue_.empty() || closing_.load()) {
            writing_ = false;
            return;
        }

        ws_.text(true);
        ws_.async_write(
            net::buffer(write_queue_.front()),
            beast::bind_front_handler(&session::on_write, shared_from_this()));
    }

    void on_write(error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);
        
        if (ec) {
            g_logger->sessionError(session_id_, "Write error: {}", ec.message());
            writing_ = false;
            shutdown();
            return;
        }

        if (session_id_ > 0) {
            g_logger->messageEvent(session_id_, "OUT", write_queue_.front());
        }

        write_queue_.pop_front();
        
        // Continue writing if there are more messages
        if (!write_queue_.empty() && !closing_.load()) {
            do_write();
        } else {
            writing_ = false;
        }
    }

    void on_run() {
        // Set WebSocket options
        beast::get_lowest_layer(ws_).expires_after(cfg_.session_timeout);

        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_.set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res) {
                res.set(http::field::server, 
                       std::string(BOOST_BEAST_VERSION_STRING) + " websocket-messenger");
            }));

        ws_.async_accept(beast::bind_front_handler(&session::on_accept, shared_from_this()));
    }

    void on_accept(error_code ec) {
        if (ec) {
            g_logger->error("[C{}] Accept error: {}", connection_id_, ec.message());
            return;
        }

        g_logger->connectionEvent("WebSocket handshake completed [C{}]", connection_id_);
        do_read();
    }

    void do_read() {
        if (closing_.load()) return;
        
        ws_.async_read(buffer_, beast::bind_front_handler(&session::on_read, shared_from_this()));
    }

    void on_read(error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);

        if (ec == websocket::error::closed) {
            g_logger->sessionInfo(session_id_, "WebSocket closed by client");
            safe_remove_session();
            return;
        }

        if (ec) {
            g_logger->sessionError(session_id_, "Read error: {}", ec.message());
            safe_remove_session();
            return;
        }

        // Reset timeout
        beast::get_lowest_layer(ws_).expires_after(cfg_.session_timeout);

        // Process message
        auto message = beast::buffers_to_string(buffer_.data());
        buffer_.consume(buffer_.size());

        // Validate message size
        if (message.size() > cfg_.max_message_size) {
            g_logger->sessionWarning(session_id_, "Message too large: {} bytes", message.size());
            json error_response = {
                {"type", "error"},
                {"message", "Message too large"}
            };
            send_message(error_response);
            do_read();
            return;
        }

        if (session_id_ > 0) {
            g_logger->messageEvent(session_id_, "IN", message);
        }

        process_message(message);
        
        if (!closing_.load()) {
            do_read();
        }
    }

    void process_message(const std::string& message) {
        try {
            json parsed = json::parse(message);
            
            if (!parsed.contains("type") || !parsed["type"].is_string()) {
                g_logger->sessionWarning(session_id_, "Missing or invalid 'type' field");
                send_error("Missing or invalid 'type' field");
                return;
            }

            std::string type = parsed["type"];
            
            if (type == "auth") {
                handle_auth_message(parsed);
            } else if (!authenticated_) {
                g_logger->sessionWarning(session_id_, "Received '{}' message without authentication", type);
                send_error("Authentication required");
            } else if (type == "message" || type == "broadcast") {
                handle_chat_message(parsed, type);
            } else if (type == "ping") {
                handle_ping_message();
            } else if (type == "join_room") {
                handle_join_room_message(parsed);
            } else {
                g_logger->sessionWarning(session_id_, "Unknown message type: {}", type);
                send_error("Unknown message type: " + type);
            }
        } catch (const json::parse_error& e) {
            g_logger->sessionWarning(session_id_, "JSON parse error: {}", e.what());
            send_error("Invalid JSON format");
        }
    }

    void handle_auth_message(const json& parsed) {
        if (!parsed.contains("token") || !parsed.contains("username")) {
            g_logger->warn("[C{}] Missing token or username fields", connection_id_);
            send_error("Missing token or username");
            return;
        }

        std::string token = parsed["token"];
        std::string username = parsed["username"];

        // Validate token
        if (token != cfg_.auth_token) {
            g_logger->securityEvent("Invalid token from [C{}]", connection_id_);
            send_error("Invalid token");
            shutdown();
            return;
        }

        // Validate username
        if (!g_session_manager->is_valid_username(username)) {
            g_logger->warn("[C{}] Invalid username: '{}'", connection_id_, username);
            send_error("Invalid username. Must be 3-20 alphanumeric characters");
            return;
        }

        if (g_session_manager->is_username_taken(username)) {
            g_logger->info("Username '{}' already taken", username);
            send_error("Username already taken");
            shutdown();
            return;
        }

        // Authentication successful
        session_id_ = ++next_session_id_;
        username_ = username;
        authenticated_ = true;

        g_logger->connectionEvent("User authenticated [S{}]: {}", session_id_, username_);

        // Add to session manager
        g_session_manager->add_session(session_id_, username_, shared_from_this());

        // Send responses
        json auth_response = {{"type", "auth"}, {"message", "AUTH_RESPONSE"}};
        send_message(auth_response);

        json user_list = {
            {"type", "user_list"},
            {"users", g_session_manager->get_user_list()}
        };
        send_message(user_list);

        // Send room history
        send_room_history();

        // Notify others
        json user_joined = {{"type", "user_joined"}, {"username", username_}};
        g_session_manager->broadcast_message(user_joined, session_id_);
    }

    void handle_chat_message(const json& parsed, const std::string& type) {
        std::string message_field = (type == "message") ? "data" : "message";
        
        if (!parsed.contains(message_field)) {
            send_error("Missing message content");
            return;
        }

        std::string msg_content = parsed[message_field];
        if (msg_content.empty() || msg_content.size() > cfg_.max_message_size) {
            send_error("Invalid message content");
            return;
        }

        json broadcast_message = {
            {"type", type},
            {"from", username_},
            {"sender_id", session_id_},
            {"timestamp", make_timestamp()},
            {"room", current_room_}
        };
        broadcast_message[message_field] = msg_content;

        // Add to history if enabled
        if (cfg_.enable_message_history) {
            g_session_manager->add_message_to_history(broadcast_message, current_room_);
        }

        // Broadcast to room
        g_session_manager->broadcast_message(broadcast_message, session_id_, current_room_);
        
        g_logger->sessionInfo(session_id_, "Message sent: {}", msg_content);
    }

    void handle_ping_message() {
        json pong_response = {
            {"type", "pong"},
            {"timestamp", make_timestamp()}
        };
        send_message(pong_response);
    }

    void handle_join_room_message(const json& parsed) {
        if (!parsed.contains("room")) {
            send_error("Missing room name");
            return;
        }

        std::string room = parsed["room"];
        if (!g_session_manager->is_valid_room_name(room)) {
            send_error("Invalid room name");
            return;
        }

        if (room != current_room_) {
            current_room_ = room;
            g_logger->sessionInfo(session_id_, "Joined room: {}", room);
            
            json room_joined = {
                {"type", "room_joined"},
                {"room", room}
            };
            send_message(room_joined);
            
            // Send room history
            send_room_history();
        }
    }

    void send_error(const std::string& message) {
        json error_response = {
            {"type", "error"},
            {"message", message}
        };
        send_message(error_response);
    }

    void on_close(error_code ec) {
        if (ec) {
            g_logger->sessionError(session_id_, "Close error: {}", ec.message());
        }

        safe_remove_session();
        
        if (session_id_ > 0) {
            g_logger->connectionEvent("Session closed [S{}]", session_id_);
        }
    }

    void safe_remove_session() {
        bool expected = false;
        if (removed_.compare_exchange_strong(expected, true)) {
            if (session_id_ > 0) {
                g_session_manager->remove_session(session_id_);
            }
        }
    }
};

std::atomic<int> session::next_session_id_{0};
std::atomic<int> session::temp_connection_id_{0};

// SessionManager implementations
void SessionManager::add_session(int id, const std::string& username, std::shared_ptr<session> session_ptr) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_[id] = std::move(session_ptr);
    session_to_username_[id] = username;
    used_usernames_.insert(username);
    g_logger->metricsEvent("User added: {}. Total sessions: {}", username, sessions_.size());
}

void SessionManager::remove_session(int id) {
    std::vector<std::shared_ptr<session>> targets;
    std::string username;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it_name = session_to_username_.find(id);
        if (it_name != session_to_username_.end()) {
            username = it_name->second;
            used_usernames_.erase(username);
            session_to_username_.erase(it_name);
            g_logger->info("Username freed: {}", username);
        }

        // Collect other sessions for notification
        for (auto& [sid, sp] : sessions_) {
            if (sid != id && sp) {
                targets.push_back(sp);
            }
        }

        sessions_.erase(id);
    }

    // Notify other users
    if (!username.empty()) {
        json user_left = {{"type", "user_left"}, {"username", username}};
        for (auto& s : targets) {
            s->send_message(user_left);
        }
    }

    g_logger->metricsEvent("User disconnected. Total sessions: {}", get_user_count());
}

void SessionManager::broadcast_message(const json& message, int sender_id, const std::string& room) {
    std::vector<std::shared_ptr<session>> targets;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, sp] : sessions_) {
            if (id != sender_id && sp) {
                targets.push_back(sp);
            }
        }
    }

    g_logger->debug("Broadcasting to {} recipients in room '{}'", targets.size(), room);
    
    for (auto& s : targets) {
        s->send_message(message);
    }
}

void SessionManager::add_message_to_history(const json& message, const std::string& room) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& history = room_history_[room];
    history.push_back(message);
    
    // Limit history size
    while (history.size() > cfg_.max_history_per_room) {
        history.pop_front();
    }
}

std::vector<json> SessionManager::get_room_history(const std::string& room, size_t max_messages) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = room_history_.find(room);
    if (it == room_history_.end()) {
        return {};
    }
    
    const auto& history = it->second;
    std::vector<json> result;
    
    size_t start = history.size() > max_messages ? history.size() - max_messages : 0;
    for (size_t i = start; i < history.size(); ++i) {
        result.push_back(history[i]);
    }
    
    return result;
}

size_t SessionManager::get_user_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

bool SessionManager::is_username_taken(const std::string& username) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return used_usernames_.find(username) != used_usernames_.end();
}

std::vector<std::string> SessionManager::get_user_list() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> users;
    users.reserve(session_to_username_.size());
    
    for (const auto& [id, username] : session_to_username_) {
        users.push_back(username);
    }
    
    std::sort(users.begin(), users.end());
    return users;
}

bool SessionManager::is_valid_username(const std::string& username) const {
    if (username.empty() || 
        username.length() < cfg_.min_username_length || 
        username.length() > cfg_.max_username_length) {
        return false;
    }
    
    // Check for valid characters (alphanumeric + underscore)
    return std::all_of(username.begin(), username.end(), 
                       [](char c) { return std::isalnum(c) || c == '_'; });
}

bool SessionManager::is_valid_room_name(const std::string& room) const {
    if (room.empty() || room.length() > 50) {
        return false;
    }
    
    return std::all_of(room.begin(), room.end(), 
                       [](char c) { return std::isalnum(c) || c == '_' || c == '-'; });
}

void SessionManager::shutdown_all() {
    shutdown_initiated_ = true;
    std::vector<std::shared_ptr<session>> sessions_copy;
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, session_ptr] : sessions_) {
            sessions_copy.push_back(session_ptr);
        }
    }
    
    g_logger->info("Shutting down {} sessions", sessions_copy.size());
    
    for (auto& session_ptr : sessions_copy) {
        session_ptr->shutdown();
    }
    
    // Give sessions time to close gracefully
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_.clear();
        used_usernames_.clear();
        session_to_username_.clear();
    }
    
    g_logger->info("All sessions shut down");
}

class listener : public std::enable_shared_from_this<listener> {
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    const Config& cfg_;
    std::atomic<bool> accepting_{false};

public:
    listener(net::io_context& ioc, tcp::endpoint endpoint, const Config& cfg)
        : ioc_(ioc), acceptor_(net::make_strand(ioc)), cfg_(cfg) {
        
        error_code ec;

        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            throw std::runtime_error("Failed to open acceptor: " + ec.message());
        }

        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            throw std::runtime_error("Failed to set reuse_address: " + ec.message());
        }

        acceptor_.bind(endpoint, ec);
        if (ec) {
            throw std::runtime_error("Failed to bind acceptor: " + ec.message());
        }

        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            throw std::runtime_error("Failed to start listening: " + ec.message());
        }

        auto local_ep = acceptor_.local_endpoint();
        g_logger->serverEvent("Acceptor bound to {}:{}", 
                             local_ep.address().to_string(), local_ep.port());
    }

    void run() {
        accepting_ = true;
        do_accept();
    }

    void stop() {
        accepting_ = false;
        if (acceptor_.is_open()) {
            error_code ec;
            acceptor_.close(ec);
            if (ec) {
                g_logger->error("Error closing acceptor: {}", ec.message());
            }
        }
    }

private:
    void do_accept() {
        if (!accepting_.load() || !acceptor_.is_open()) {
            return;
        }

        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(&listener::on_accept, shared_from_this()));
    }

    void on_accept(error_code ec, tcp::socket socket) {
        if (ec) {
            if (ec != net::error::operation_aborted) {
                g_logger->error("Accept error: {}", ec.message());
            }
            return;
        }

        try {
            auto remote_ep = socket.remote_endpoint();
            g_logger->connectionEvent("New connection from {}:{}", 
                                     remote_ep.address().to_string(), remote_ep.port());
            
            std::make_shared<session>(std::move(socket), cfg_)->run();
        } catch (const std::exception& e) {
            g_logger->error("Error handling new connection: {}", e.what());
        }

        // Continue accepting
        do_accept();
    }
};

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    // Load and validate configuration
    Config cfg;
    try {
        cfg.load(argc, argv);
        cfg.validate();
        
        // Initialize logger first
        g_logger = std::make_unique<Logger>(cfg.log_file, cfg.log_level, 
                                           cfg.log_max_size, cfg.log_max_files);
        
        // Print configuration for debugging
        if (cfg.log_level == "DEBUG") {
            cfg.print_config();
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Configuration error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    // Initialize session manager
    g_session_manager = std::make_unique<SessionManager>(cfg);

    try {
        // Prepare network
        auto const address = net::ip::make_address(cfg.address);
        auto const port = cfg.port;
        auto const threads = std::max<int>(1, cfg.threads);

        net::io_context ioc{threads};

        // Setup signal handling for graceful shutdown
        net::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](error_code const&, int signal) {
            g_logger->serverEvent("Shutdown signal received ({})", signal);
            g_shutdown_requested = true;
            
            // Shutdown sessions first
            g_session_manager->shutdown_all();
            
            // Stop io_context
            ioc.stop();
            
            g_logger->serverEvent("Server shutdown complete");
        });

        // Create and start listener
        auto lst = std::make_shared<listener>(ioc, tcp::endpoint{address, port}, cfg);
        lst->run();

        g_logger->serverEvent("WebSocket Messenger Server started");
        g_logger->serverEvent("Listening on {}:{}", address.to_string(), port);
        g_logger->serverEvent("Using {} worker threads", threads);
        g_logger->serverEvent("Ready to accept connections");

        // Start worker threads
        std::vector<std::thread> worker_threads;
        worker_threads.reserve(threads - 1);
        
        for (int i = 0; i < threads - 1; ++i) {
            worker_threads.emplace_back([&ioc, i]() {
                g_logger->info("Worker thread {} started", i + 1);
                ioc.run();
                g_logger->info("Worker thread {} stopped", i + 1);
            });
        }

        // Run on main thread
        g_logger->info("Main thread starting");
        ioc.run();
        g_logger->info("Main thread stopped");

        // Wait for worker threads
        for (auto& t : worker_threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        g_logger->serverEvent("All threads joined. Exiting normally.");
        
        // Cleanup in proper order
        g_session_manager.reset();
        
        // Final flush and cleanup
        if (g_logger) {
            g_logger->flush();
            g_logger.reset();
        }
        
        // Now it's safe to shutdown spdlog
        spdlog::shutdown();
        
    } catch (const std::exception& e) {
        if (g_logger) {
            g_logger->error("Server error: {}", e.what());
        } else {
            std::cerr << "Server error: " << e.what() << std::endl;
        }
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}