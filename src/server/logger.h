#pragma once 
#include <spdlog/spdlog.h>
#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <memory>
#include <string>
#include <string_view>

class Logger {
public:
    Logger(const std::string& log_file, const std::string& log_level,
           size_t max_size = 5 * 1024 * 1024, size_t max_files = 3);
    ~Logger();

    void info(const std::string& message);
    void debug(const std::string& message);
    void warn(const std::string& message);
    void error(const std::string& message);


    template<typename... Args> void info(const char* fmt, Args&&... args) { logger_->info(fmt, std::forward<Args>(args)...); }
    template<typename... Args> void debug(const char* fmt, Args&&... args) { logger_->debug(fmt, std::forward<Args>(args)...); }
    template<typename... Args> void warn(const char* fmt, Args&&... args)  { logger_->warn(fmt, std::forward<Args>(args)...); }
    template<typename... Args> void error(const char* fmt, Args&&... args) { logger_->error(fmt, std::forward<Args>(args)...); }


    template<typename... Args> void serverEvent(const char* fmt, Args&&... args) { info(fmt, std::forward<Args>(args)...); }
    template<typename... Args> void connectionEvent(const char* fmt, Args&&... args) { info(fmt, std::forward<Args>(args)...); }
    template<typename... Args> void metricsEvent(const char* fmt, Args&&... args) { info(fmt, std::forward<Args>(args)...); }
    template<typename... Args> void securityEvent(const char* fmt, Args&&... args) { warn(fmt, std::forward<Args>(args)...); }

    template<typename... Args> void sessionInfo(int sid, const char* fmt, Args&&... args) {
        logger_->info("[S{}] {}", sid, fmt::format(fmt, std::forward<Args>(args)...));
    }
    template<typename... Args> void sessionWarning(int sid, const char* fmt, Args&&... args) {
        logger_->warn("[S{}] {}", sid, fmt::format(fmt, std::forward<Args>(args)...));
    }
    template<typename... Args> void sessionError(int sid, const char* fmt, Args&&... args) {
        logger_->error("[S{}] {}", sid, fmt::format(fmt, std::forward<Args>(args)...));
    }

    void messageEvent(int sid, std::string_view direction, std::string_view payload) {
        logger_->debug("[S{}] {} {}", sid, direction, payload);
    }

    void setLevel(const std::string& level);
    void flush();

private:
    std::shared_ptr<spdlog::logger> logger_;
    void setupSinks(const std::string& log_file, size_t max_size, size_t max_files);
    void setupLogger(const std::string& log_level);
};