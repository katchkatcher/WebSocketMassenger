#ifndef LOGGER_H
#define LOGGER_H

#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/fmt/ostr.h>
#include <boost/system/error_code.hpp>
#include <memory>
#include <string>
#include <iostream>  // Добавили этот include для std::cerr

class Logger {
public:
    Logger(const std::string& log_file, const std::string& log_level, 
           size_t max_size = 5 * 1024 * 1024, size_t max_files = 3);
    ~Logger();

    // Basic log methods - используем простые перегрузки вместо шаблонов
    void info(const std::string& message);
    void debug(const std::string& message);
    void warn(const std::string& message);
    void error(const std::string& message);

    // Template methods для форматирования
    template<typename... Args>
    void info(const std::string& fmt, Args&&... args) {
        try {
            logger_->info(fmt, std::forward<Args>(args)...);
        } catch (const std::exception& e) {
            logger_->error("Log formatting error in info: {}", e.what());
        }
    }

    template<typename... Args>
    void debug(const std::string& fmt, Args&&... args) {
        try {
            logger_->debug(fmt, std::forward<Args>(args)...);
        } catch (const std::exception& e) {
            logger_->error("Log formatting error in debug: {}", e.what());
        }
    }

    template<typename... Args>
    void warn(const std::string& fmt, Args&&... args) {
        try {
            logger_->warn(fmt, std::forward<Args>(args)...);
        } catch (const std::exception& e) {
            logger_->error("Log formatting error in warn: {}", e.what());
        }
    }

    template<typename... Args>
    void error(const std::string& fmt, Args&&... args) {
        try {
            logger_->error(fmt, std::forward<Args>(args)...);
        } catch (const std::exception& e) {
            // Fallback для ошибок в error логах
            std::cerr << "Critical log error: " << e.what() << std::endl;
        }
    }

    // Specialized methods
    template<typename... Args>
    void sessionInfo(int session_id, const std::string& fmt, Args&&... args) {
        try {
            auto msg = fmt::format(fmt, std::forward<Args>(args)...);
            logger_->info("[S{}] {}", session_id, msg);
        } catch (const std::exception& e) {
            logger_->error("Session log formatting error: {}", e.what());
        }
    }

    template<typename... Args>
    void sessionError(int session_id, const std::string& fmt, Args&&... args) {
        try {
            auto msg = fmt::format(fmt, std::forward<Args>(args)...);
            logger_->error("[S{}] {}", session_id, msg);
        } catch (const std::exception& e) {
            logger_->error("Session error log formatting error: {}", e.what());
        }
    }

    template<typename... Args>
    void sessionDebug(int session_id, const std::string& fmt, Args&&... args) {
        try {
            auto msg = fmt::format(fmt, std::forward<Args>(args)...);
            logger_->debug("[S{}] {}", session_id, msg);
        } catch (const std::exception& e) {
            logger_->error("Session debug log formatting error: {}", e.what());
        }
    }

    template<typename... Args>
    void sessionWarning(int session_id, const std::string& fmt, Args&&... args) {
        try {
            auto msg = fmt::format(fmt, std::forward<Args>(args)...);
            logger_->warn("[S{}] {}", session_id, msg);
        } catch (const std::exception& e) {
            logger_->error("Session warning log formatting error: {}", e.what());
        }
    }

    // Boost error code logging
    void errorCode(const boost::system::error_code& ec, const std::string& context) {
        logger_->error("{}: {} (code: {})", context, ec.message(), ec.value());
    }

    template<typename... Args>
    void serverEvent(const std::string& fmt, Args&&... args) {
        try {
            auto msg = fmt::format(fmt, std::forward<Args>(args)...);
            logger_->info("🚀 {}", msg);
        } catch (const std::exception& e) {
            logger_->error("Server event log formatting error: {}", e.what());
        }
    }

    template<typename... Args>
    void connectionEvent(const std::string& fmt, Args&&... args) {
        try {
            auto msg = fmt::format(fmt, std::forward<Args>(args)...);
            logger_->info("🔗 {}", msg);
        } catch (const std::exception& e) {
            logger_->error("Connection event log formatting error: {}", e.what());
        }
    }

    // Message logging with direction
    void messageEvent(int session_id, const std::string& direction, const std::string& message) {
        std::string icon = (direction == "IN") ? "📥" : "📤";
        logger_->debug("{} [S{}] {}: {}", icon, session_id, direction, message);
    }

    template<typename... Args>
    void metricsEvent(const std::string& fmt, Args&&... args) {
        try {
            auto msg = fmt::format(fmt, std::forward<Args>(args)...);
            logger_->info("📊 {}", msg);
        } catch (const std::exception& e) {
            logger_->error("Metrics event log formatting error: {}", e.what());
        }
    }

    template<typename... Args>
    void securityEvent(const std::string& fmt, Args&&... args) {
        try {
            auto msg = fmt::format(fmt, std::forward<Args>(args)...);
            logger_->warn("🔒 SECURITY: {}", msg);
        } catch (const std::exception& e) {
            logger_->error("Security event log formatting error: {}", e.what());
        }
    }

    void setLevel(const std::string& level);
    void flush();

private:
    std::shared_ptr<spdlog::logger> logger_;
    void setupSinks(const std::string& log_file, size_t max_size, size_t max_files);
    void setupLogger(const std::string& log_level);
};

#endif