#ifndef LOGGER_H
#define LOGGER_H

#include <Arduino.h>


enum LogLevel {
    LOG_ERROR = 0,
    LOG_WARN = 1,
    LOG_INFO = 2,
    LOG_DEBUG = 3
};

class Logger {
public:
    static void init();
    static void log(LogLevel level, const char* tag, const char* message);
    static void logf(LogLevel level, const char* tag, const char* format, ...);
    static void error(const char* tag, const char* message);
    static void warn(const char* tag, const char* message);
    static void info(const char* tag, const char* message);
    static void debug(const char* tag, const char* message);

private:
    static const char* getLevelString(LogLevel level);
};

// Convenience macros
#define LOG_E(tag, msg) Logger::error(tag, msg)
#define LOG_W(tag, msg) Logger::warn(tag, msg)
#define LOG_I(tag, msg) Logger::info(tag, msg)
#define LOG_D(tag, msg) Logger::debug(tag, msg)

#define LOGF_E(tag, fmt, ...) Logger::logf(LOG_ERROR, tag, fmt, ##__VA_ARGS__)
#define LOGF_W(tag, fmt, ...) Logger::logf(LOG_WARN, tag, fmt, ##__VA_ARGS__)
#define LOGF_I(tag, fmt, ...) Logger::logf(LOG_INFO, tag, fmt, ##__VA_ARGS__)
#define LOGF_D(tag, fmt, ...) Logger::logf(LOG_DEBUG, tag, fmt, ##__VA_ARGS__)

#endif
