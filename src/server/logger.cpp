#include "logger.h"
#include <stdexcept>

Logger::Logger(const std::string& log_file, const std::string& log_level, 
               size_t max_size, size_t max_files) {
    static std::once_flag pool_once;
    std::call_once(pool_once, []{
        if (!spdlog::thread_pool()) spdlog::init_thread_pool(8192, 1);
    });
    setupSinks(log_file, max_size, max_files);
    setupLogger(log_level);
    logger_->flush_on(spdlog::level::warn);
    logger_->info("📝 Log level set to: {}", log_level);
    logger_->info("🚀 Logger initialized successfully");
    logger_->info("📁 Log file: {}, Max size: {}MB, Max files: {}", log_file, max_size / 1024 / 1024, max_files);
    logger_->flush();
}

Logger::~Logger() {
    try {
        if (logger_) {
            logger_->info("🛑 Logger shutting down");
            logger_->flush();
            auto name = logger_->name();
            spdlog::drop(name);
        }
        spdlog::shutdown();
    } catch (...) {
        // swallow
    }
}

void Logger::setupSinks(const std::string& log_file, size_t max_size, size_t max_files) {
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [thread %t] %v");
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(log_file, max_size, max_files);
    file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");

    std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};

    if (auto existing = spdlog::get("websocket_logger")) {
        spdlog::drop("websocket_logger");
    }

    logger_ = std::make_shared<spdlog::async_logger>(
        "websocket_logger", sinks.begin(), sinks.end(), spdlog::thread_pool(),
        spdlog::async_overflow_policy::block);
    spdlog::register_logger(logger_);
}

void Logger::setupLogger(const std::string& log_level) {
    setLevel(log_level);
}

void Logger::setLevel(const std::string& level) {
    auto lvl = spdlog::level::info;
    if (level == "DEBUG") lvl = spdlog::level::debug;
    else if (level == "WARN") lvl = spdlog::level::warn;
    else if (level == "ERROR") lvl = spdlog::level::err;
    logger_->set_level(lvl);
}

void Logger::flush() { if (logger_) logger_->flush(); }


void Logger::info(const std::string& message) { logger_->info("{}", message); }
void Logger::debug(const std::string& message) { logger_->debug("{}", message); }
void Logger::warn(const std::string& message) { logger_->warn("{}", message); }
void Logger::error(const std::string& message) { logger_->error("{}", message); }