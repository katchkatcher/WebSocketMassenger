#include "logger.h"
#include <stdexcept>
#include <algorithm>
#include <iostream>

Logger::Logger(const std::string& log_file, const std::string& log_level, 
               size_t max_size, size_t max_files) {
    try {
        // Check if thread pool already exists, if not - create it
        if (!spdlog::thread_pool()) {
            spdlog::init_thread_pool(8192, 1);
        }
        
        setupSinks(log_file, max_size, max_files);
        setupLogger(log_level);
        
        logger_->info("🚀 Logger initialized successfully");
        logger_->info("📁 Log file: {}, Max size: {}MB, Max files: {}", 
                     log_file, max_size / 1024 / 1024, max_files);
        
        // Force flush to ensure initialization message is written
        logger_->flush();
        
    } catch (const spdlog::spdlog_ex& ex) {
        throw std::runtime_error("Logger initialization failed: " + std::string(ex.what()));
    }
}

Logger::~Logger() {
    try {
        if (logger_) {
            logger_->info("🛑 Logger shutting down");
            logger_->flush();
            
            // Unregister logger before shutdown
            spdlog::drop(logger_->name());
            logger_.reset();
        }
        
        // Note: We don't call spdlog::shutdown() here as it may be called by main
        
    } catch (const std::exception& e) {
        std::cerr << "Logger destructor error: " << e.what() << std::endl;
    }
}

void Logger::setupSinks(const std::string& log_file, size_t max_size, size_t max_files) {
    try {
        // Console sink with colors
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [thread %t] %v");
        
        // Rotating file sink
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file, max_size, max_files);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");
        
        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        
        // Create async logger
        logger_ = std::make_shared<spdlog::async_logger>(
            "websocket_logger",
            sinks.begin(), 
            sinks.end(),
            spdlog::thread_pool(),
            spdlog::async_overflow_policy::block
        );
        
        // Register logger globally for easy access
        spdlog::register_logger(logger_);
        
    } catch (const spdlog::spdlog_ex& ex) {
        throw std::runtime_error("Sink setup failed: " + std::string(ex.what()));
    }
}

void Logger::setupLogger(const std::string& log_level) {
    std::string upper_level = log_level;
    std::transform(upper_level.begin(), upper_level.end(), upper_level.begin(), ::toupper);
    
    if (upper_level == "DEBUG") {
        logger_->set_level(spdlog::level::debug);
    } else if (upper_level == "INFO") {
        logger_->set_level(spdlog::level::info);
    } else if (upper_level == "WARN") {
        logger_->set_level(spdlog::level::warn);
    } else if (upper_level == "ERROR") {
        logger_->set_level(spdlog::level::err);
    } else {
        throw std::invalid_argument("Invalid log level: " + log_level);
    }
    
    logger_->info("📝 Log level set to: {}", upper_level);
}

void Logger::setLevel(const std::string& level) {
    setupLogger(level);
}

void Logger::flush() {
    if (logger_) {
        logger_->flush();
    }
}

// Basic string methods
void Logger::info(const std::string& message) {
    logger_->info(message);
}

void Logger::debug(const std::string& message) {
    logger_->debug(message);
}

void Logger::warn(const std::string& message) {
    logger_->warn(message);
}

void Logger::error(const std::string& message) {
    logger_->error(message);
}