#include "config.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <algorithm>

namespace po = boost::program_options;
namespace net = boost::asio;

void Config::load(int argc, char* argv[]) {
    po::options_description desc("WebSocket Messenger Server Options");
    desc.add_options()
        ("help,h", "Show help message")
        ("address,a", po::value<std::string>(&address)->default_value("127.0.0.1"), "Bind address (default: 127.0.0.1)")
        ("port,p", po::value<unsigned short>(&port)->default_value(8080), "Port number (default: 8080)")
        ("threads,t", po::value<int>(&threads)->default_value(1), "Number of worker threads (default: 1)")
        ("config,c", po::value<std::string>(), "JSON configuration file")
        ("auth-token", po::value<std::string>(&auth_token), "Authentication token")
        ("log-file", po::value<std::string>(&log_file), "Log file path")
        ("log-level", po::value<std::string>(&log_level)->default_value("INFO"), "Log level (DEBUG/INFO/WARN/ERROR)")
        ("max-queue-size", po::value<size_t>(&max_queue_size)->default_value(1000), "Maximum write queue size per session")
        ("max-message-size", po::value<size_t>(&max_message_size)->default_value(65536), "Maximum message size in bytes")
        ("session-timeout", po::value<int>(), "Session timeout in seconds")
        ("enable-history", po::value<bool>(&enable_message_history)->default_value(false), "Enable message history");

    po::variables_map vm;
    
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (const po::error& e) {
        throw std::runtime_error("Command line parsing error: " + std::string(e.what()));
    }

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        std::cout << "\nExample usage:\n";
        std::cout << "  " << argv[0] << " --address 0.0.0.0 --port 8080 --threads 4\n";
        std::cout << "  " << argv[0] << " --config server_config.json\n";
        std::cout << "\nEnvironment variables (highest priority):\n";
        std::cout << "  WS_ADDRESS, WS_PORT, WS_THREADS, WS_AUTH_TOKEN, WS_LOG_LEVEL\n";
        exit(EXIT_SUCCESS);
    }

    // Load from JSON config file if specified
    if (vm.count("config")) {
        std::string config_file = vm["config"].as<std::string>();
        std::ifstream f(config_file);
        if (!f.is_open()) {
            throw std::runtime_error("Failed to open config file: " + config_file);
        }
        
        try {
            nlohmann::json j = nlohmann::json::parse(f);
            
            // Network settings
            if (j.contains("address")) address = j["address"].get<std::string>();
            if (j.contains("port")) port = j["port"].get<unsigned short>();
            if (j.contains("threads")) threads = j["threads"].get<int>();
            
            // Auth settings
            if (j.contains("auth_token")) auth_token = j["auth_token"].get<std::string>();
            if (j.contains("session_timeout")) {
                session_timeout = std::chrono::seconds(j["session_timeout"].get<int>());
            }
            
            // Logging settings
            if (j.contains("log_file")) log_file = j["log_file"].get<std::string>();
            if (j.contains("log_level")) log_level = j["log_level"].get<std::string>();
            if (j.contains("log_max_size")) log_max_size = j["log_max_size"].get<size_t>();
            if (j.contains("log_max_files")) log_max_files = j["log_max_files"].get<size_t>();
            
            // Performance settings
            if (j.contains("max_queue_size")) max_queue_size = j["max_queue_size"].get<size_t>();
            if (j.contains("max_message_size")) max_message_size = j["max_message_size"].get<size_t>();
            if (j.contains("rate_limit_max_messages")) rate_limit_max_messages = j["rate_limit_max_messages"].get<size_t>();
            
            // Feature settings
            if (j.contains("enable_message_history")) enable_message_history = j["enable_message_history"].get<bool>();
            if (j.contains("max_history_per_room")) max_history_per_room = j["max_history_per_room"].get<size_t>();
            
        } catch (const nlohmann::json::exception& e) {
            throw std::runtime_error("JSON parse error in " + config_file + ": " + std::string(e.what()));
        }
    }

    // Handle session timeout from command line
    if (vm.count("session-timeout")) {
        session_timeout = std::chrono::seconds(vm["session-timeout"].as<int>());
    }

    // Environment variable overrides (highest priority)
    if (const char* env = std::getenv("WS_ADDRESS")) address = env;
    if (const char* env = std::getenv("WS_PORT")) {
        try {
            port = static_cast<unsigned short>(std::stoul(env));
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid WS_PORT value: " + std::string(env));
        }
    }
    if (const char* env = std::getenv("WS_THREADS")) {
        try {
            threads = std::stoi(env);
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid WS_THREADS value: " + std::string(env));
        }
    }
    if (const char* env = std::getenv("WS_AUTH_TOKEN")) auth_token = env;
    if (const char* env = std::getenv("WS_LOG_FILE")) log_file = env;
    if (const char* env = std::getenv("WS_LOG_LEVEL")) log_level = env;
    if (const char* env = std::getenv("WS_MAX_QUEUE_SIZE")) {
        try {
            max_queue_size = static_cast<size_t>(std::stoul(env));
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid WS_MAX_QUEUE_SIZE value: " + std::string(env));
        }
    }
}

void Config::validate() const {
    if (port == 0) {
        throw std::invalid_argument("Port must be greater than 0");
    }
    if (threads < 1 || threads > 100) {
        throw std::invalid_argument("Threads must be between 1 and 100");
    }
    if (auth_token.empty()) {
        throw std::invalid_argument("Auth token cannot be empty");
    }
    if (max_queue_size == 0 || max_queue_size > 10000) {
        throw std::invalid_argument("Max queue size must be between 1 and 10000");
    }
    if (max_message_size < 256 || max_message_size > 1024 * 1024) {
        throw std::invalid_argument("Max message size must be between 256 bytes and 1MB");
    }
    if (session_timeout.count() < 30 || session_timeout.count() > 3600) {
        throw std::invalid_argument("Session timeout must be between 30 seconds and 1 hour");
    }
    
    // Validate log level
    std::string upper_level = log_level;
    std::transform(upper_level.begin(), upper_level.end(), upper_level.begin(), ::toupper);
    if (upper_level != "DEBUG" && upper_level != "INFO" && upper_level != "WARN" && upper_level != "ERROR") {
        throw std::invalid_argument("Invalid log level: " + log_level + ". Must be DEBUG, INFO, WARN, or ERROR");
    }
    
    // Validate IP address
    boost::system::error_code ec;
    net::ip::make_address(address, ec);
    if (ec) {
        throw std::invalid_argument("Invalid IP address: " + address + " (" + ec.message() + ")");
    }
    
    if (log_file.empty()) {
        throw std::invalid_argument("Log file path cannot be empty");
    }
    
    if (min_username_length >= max_username_length) {
        throw std::invalid_argument("Min username length must be less than max username length");
    }
}

void Config::print_config() const {
    std::cout << "=== WebSocket Messenger Configuration ===\n";
    std::cout << "Network:\n";
    std::cout << "  Address: " << address << "\n";
    std::cout << "  Port: " << port << "\n";
    std::cout << "  Threads: " << threads << "\n";
    std::cout << "Auth:\n";
    std::cout << "  Token: " << (auth_token.empty() ? "(empty)" : "***") << "\n";
    std::cout << "  Session timeout: " << session_timeout.count() << "s\n";
    std::cout << "Logging:\n";
    std::cout << "  File: " << log_file << "\n";
    std::cout << "  Level: " << log_level << "\n";
    std::cout << "  Max size: " << log_max_size / 1024 / 1024 << "MB\n";
    std::cout << "  Max files: " << log_max_files << "\n";
    std::cout << "Performance:\n";
    std::cout << "  Max queue size: " << max_queue_size << "\n";
    std::cout << "  Max message size: " << max_message_size << " bytes\n";
    std::cout << "  Rate limit: " << rate_limit_max_messages << " msgs/" << rate_limit_window.count() << "ms\n";
    std::cout << "Features:\n";
    std::cout << "  Message history: " << (enable_message_history ? "enabled" : "disabled") << "\n";
    std::cout << "  Max history per room: " << max_history_per_room << "\n";
    std::cout << "========================================\n";
}