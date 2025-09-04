#include "config.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <algorithm>

namespace po = boost::program_options;
using json = nlohmann::json;

static const char* envc(const char* k) { return std::getenv(k); }

void Config::load(int argc, char* argv[]) {
    po::options_description desc("WebSocket Messenger Server Options");
    desc.add_options()
        ("help,h", "Show help")
        ("config,c", po::value<std::string>(), "Path to JSON config (optional)")
        ("address,a", po::value<std::string>(), "Bind address")
        ("port,p", po::value<unsigned short>(), "Port")
        ("threads,t", po::value<int>(), "Worker threads (>=1)")
        ("auth-token", po::value<std::string>(), "Auth token")
        ("log-file", po::value<std::string>(), "Log file path")
        ("log-level", po::value<std::string>(), "Log level (DEBUG/INFO/WARN/ERROR)")
        ("log-max-size", po::value<size_t>(), "Log rotate size (bytes)")
        ("log-max-files", po::value<size_t>(), "Log rotate file count")
        ("max-queue-size", po::value<size_t>(), "Max write queue per session")
        ("max-message-size", po::value<size_t>(), "Max WS message size (bytes)")
        ("rate-limit-window-ms", po::value<int>(), "Rate limit window (ms)")
        ("rate-limit-max-messages", po::value<size_t>(), "Rate limit messages per window")
        ("session-timeout", po::value<int>(), "Session timeout (sec)")
        ("enable-history", po::value<bool>(), "Enable message history")
        ("max-history-per-room", po::value<size_t>(), "Max history per room");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << "\n\nEnvironment (highest priority):\n"
                  << "  WSM_ADDRESS, WSM_PORT, WSM_THREADS, WSM_AUTH_TOKEN\n"
                  << "  WSM_LOG_FILE, WSM_LOG_LEVEL, WSM_LOG_MAX_SIZE, WSM_LOG_MAX_FILES\n"
                  << "  WSM_MAX_QUEUE_SIZE, WSM_MAX_MESSAGE_SIZE\n"
                  << "  WSM_RATE_LIMIT_WINDOW_MS, WSM_RATE_LIMIT_MAX_MESSAGES\n"
                  << "  WSM_SESSION_TIMEOUT, WSM_ENABLE_HISTORY, WSM_MAX_HISTORY_PER_ROOM\n";
        std::exit(EXIT_SUCCESS);
    }


    std::string json_path;
    if (vm.count("config")) json_path = vm["config"].as<std::string>();
    else { std::ifstream probe("server.json"); if (probe.good()) json_path = "server.json"; }

    if (!json_path.empty()) {
        std::ifstream f(json_path);
        if (!f) throw std::runtime_error("Failed to open config file: " + json_path);
        json j = json::parse(f, nullptr, true, true);
        if (j.contains("address")) address = j["address"].get<std::string>();
        if (j.contains("port")) port = j["port"].get<unsigned short>();
        if (j.contains("threads")) threads = j["threads"].get<int>();
        if (j.contains("auth_token")) auth_token = j["auth_token"].get<std::string>();
        if (j.contains("log_file")) log_file = j["log_file"].get<std::string>();
        if (j.contains("log_level")) log_level = j["log_level"].get<std::string>();
        if (j.contains("log_max_size")) log_max_size = j["log_max_size"].get<size_t>();
        if (j.contains("log_max_files")) log_max_files = j["log_max_files"].get<size_t>();
        if (j.contains("max_queue_size")) max_queue_size = j["max_queue_size"].get<size_t>();
        if (j.contains("max_message_size")) max_message_size = j["max_message_size"].get<size_t>();
        if (j.contains("rate_limit_window_ms")) rate_limit_window = std::chrono::milliseconds(j["rate_limit_window_ms"].get<int>());
        if (j.contains("rate_limit_max_messages")) rate_limit_max_messages = j["rate_limit_max_messages"].get<size_t>();
        if (j.contains("session_timeout")) session_timeout = std::chrono::seconds(j["session_timeout"].get<int>());
        if (j.contains("enable_message_history")) enable_message_history = j["enable_message_history"].get<bool>();
        if (j.contains("max_history_per_room")) max_history_per_room = j["max_history_per_room"].get<size_t>();
    }
    if (vm.count("address")) address = vm["address"].as<std::string>();
    if (vm.count("port")) port = vm["port"].as<unsigned short>();
    if (vm.count("threads")) threads = vm["threads"].as<int>();
    if (vm.count("auth-token")) auth_token = vm["auth-token"].as<std::string>();
    if (vm.count("log-file")) log_file = vm["log-file"].as<std::string>();
    if (vm.count("log-level")) log_level = vm["log-level"].as<std::string>();
    if (vm.count("log-max-size")) log_max_size = vm["log-max-size"].as<size_t>();
    if (vm.count("log-max-files")) log_max_files = vm["log-max-files"].as<size_t>();
    if (vm.count("max-queue-size")) max_queue_size = vm["max-queue-size"].as<size_t>();
    if (vm.count("max-message-size")) max_message_size = vm["max-message-size"].as<size_t>();
    if (vm.count("rate-limit-window-ms")) rate_limit_window = std::chrono::milliseconds(vm["rate-limit-window-ms"].as<int>());
    if (vm.count("rate-limit-max-messages")) rate_limit_max_messages = vm["rate-limit-max-messages"].as<size_t>();
    if (vm.count("session-timeout")) session_timeout = std::chrono::seconds(vm["session-timeout"].as<int>());
    if (vm.count("enable-history")) enable_message_history = vm["enable-history"].as<bool>();
    if (vm.count("max-history-per-room")) max_history_per_room = vm["max-history-per-room"].as<size_t>();

    if (auto v = envc("WSM_ADDRESS")) address = v;
    if (auto v = envc("WSM_PORT")) port = static_cast<unsigned short>(std::stoul(v));
    if (auto v = envc("WSM_THREADS")) threads = std::stoi(v);
    if (auto v = envc("WSM_AUTH_TOKEN")) auth_token = v;
    if (auto v = envc("WSM_LOG_FILE")) log_file = v;
    if (auto v = envc("WSM_LOG_LEVEL")) log_level = v;
    if (auto v = envc("WSM_LOG_MAX_SIZE")) log_max_size = static_cast<size_t>(std::stoull(v));
    if (auto v = envc("WSM_LOG_MAX_FILES")) log_max_files = static_cast<size_t>(std::stoull(v));
    if (auto v = envc("WSM_MAX_QUEUE_SIZE")) max_queue_size = static_cast<size_t>(std::stoull(v));
    if (auto v = envc("WSM_MAX_MESSAGE_SIZE")) max_message_size = static_cast<size_t>(std::stoull(v));
    if (auto v = envc("WSM_RATE_LIMIT_WINDOW_MS")) rate_limit_window = std::chrono::milliseconds(std::stoi(v));
    if (auto v = envc("WSM_RATE_LIMIT_MAX_MESSAGES")) rate_limit_max_messages = static_cast<size_t>(std::stoull(v));
    if (auto v = envc("WSM_SESSION_TIMEOUT")) session_timeout = std::chrono::seconds(std::stoi(v));
    if (auto v = envc("WSM_ENABLE_HISTORY")) {
        std::string s = v; std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        enable_message_history = (s=="1" || s=="true" || s=="yes");
    }
    if (auto v = envc("WSM_MAX_HISTORY_PER_ROOM")) max_history_per_room = static_cast<size_t>(std::stoull(v));
}

void Config::validate() const {
    if (address.empty()) throw std::invalid_argument("address must not be empty");
    if (port == 0) throw std::invalid_argument("port must be > 0");
    if (threads < 1) throw std::invalid_argument("threads must be >= 1");
    if (log_max_size == 0 || log_max_files == 0) throw std::invalid_argument("log rotation params must be > 0");
    if (max_queue_size == 0) throw std::invalid_argument("max_queue_size must be > 0");
    if (max_message_size == 0) throw std::invalid_argument("max_message_size must be > 0");
    if (rate_limit_window.count() <= 0) throw std::invalid_argument("rate_limit_window must be > 0ms");
    if (rate_limit_max_messages == 0) throw std::invalid_argument("rate_limit_max_messages must be > 0");
    if (session_timeout.count() <= 0) throw std::invalid_argument("session_timeout must be > 0s");
    if (max_history_per_room == 0) throw std::invalid_argument("max_history_per_room must be > 0");
}

void Config::print_config() const {
    std::cout << "=== WebSocket Messenger Configuration ===\n"
              << "Network:\n"
              << "  Address: " << address << "\n"
              << "  Port: " << port << "\n"
              << "  Threads: " << threads << "\n"
              << "Auth:\n"
              << "  Token: ***\n"
              << "  Session timeout: " << session_timeout.count() << "s\n"
              << "Logging:\n"
              << "  File: " << log_file << "\n"
              << "  Level: " << log_level << "\n"
              << "  Max size: " << (log_max_size / 1024 / 1024) << "MB\n"
              << "  Max files: " << log_max_files << "\n"
              << "Performance:\n"
              << "  Max queue size: " << max_queue_size << "\n"
              << "  Max message size: " << max_message_size << " bytes\n"
              << "  Rate limit: " << rate_limit_max_messages << " msgs/" << rate_limit_window.count() << "ms\n"
              << "Features:\n"
              << "  Message history: " << (enable_message_history ? "enabled" : "disabled") << "\n"
              << "  Max history per room: " << max_history_per_room << "\n"
              << "========================================\n";
}