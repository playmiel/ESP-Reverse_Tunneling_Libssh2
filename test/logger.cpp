#include "logger.h"
#include <stdarg.h>

void Logger::init() {
    Serial.begin(SERIAL_BAUD_RATE);
    while (!Serial && millis() < 5000) {
        delay(10);
    }
    Serial.println("Logger initialized");
}

void Logger::log(LogLevel level, const char* tag, const char* message) {
    if (!DEBUG_ENABLED && level > LOG_WARN) {
        return;
    }
    
    unsigned long timestamp = millis();
    Serial.printf("[%lu] %s [%s] %s\n", timestamp, getLevelString(level), tag, message);
}

void Logger::logf(LogLevel level, const char* tag, const char* format, ...) {
    if (!DEBUG_ENABLED && level > LOG_WARN) {
        return;
    }
    
    char buffer[256];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    log(level, tag, buffer);
}

void Logger::error(const char* tag, const char* message) {
    log(LOG_ERROR, tag, message);
}

void Logger::warn(const char* tag, const char* message) {
    log(LOG_WARN, tag, message);
}

void Logger::info(const char* tag, const char* message) {
    log(LOG_INFO, tag, message);
}

void Logger::debug(const char* tag, const char* message) {
    log(LOG_DEBUG, tag, message);
}

const char* Logger::getLevelString(LogLevel level) {
    switch (level) {
        case LOG_ERROR: return "ERROR";
        case LOG_WARN:  return "WARN ";
        case LOG_INFO:  return "INFO ";
        case LOG_DEBUG: return "DEBUG";
        default:        return "UNKN ";
    }
}
