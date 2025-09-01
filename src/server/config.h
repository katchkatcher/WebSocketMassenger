#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <chrono>
#include <boost/program_options.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/tcp.hpp>

// Config struct: Holds server settings with defaults. Loaded from CLI/JSON/env.
struct Config {
    // Network settings
    std::string address = "127.0.0.1";  // Localhost for dev safety (override for prod)
    unsigned short port = 8080;
    int threads = 1;
    
    // Auth settings  
    std::string auth_token = "Bearer mytoken";
    std::chrono::seconds session_timeout{300}; // 5 minutes
    
    // Logging settings
    std::string log_file = "server.log";
    std::string log_level = "INFO";
    size_t log_max_size = 5 * 1024 * 1024; // 5MB
    size_t log_max_files = 3;
    
    // Performance settings
    size_t max_queue_size = 100;
    size_t max_message_size = 4096; // 4KB
    std::chrono::milliseconds rate_limit_window{1000}; // 1 second
    size_t rate_limit_max_messages = 10;
    
    // Feature settings
    bool enable_message_history = true;
    size_t max_history_per_room = 100;
    size_t max_username_length = 20;
    size_t min_username_length = 3;

    void load(int argc, char* argv[]);  // Parse CLI, then JSON, then env overrides
    void validate() const;  // Throw if invalid (called after load)
    void print_config() const; // Для отладки
};

#endif