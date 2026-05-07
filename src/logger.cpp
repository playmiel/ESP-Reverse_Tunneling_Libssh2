#include "logger.h"
#include "ssh_config.h"
#include <stdarg.h>
#include <string.h>
#include <time.h>

namespace {
// "[YYYY-MM-DD HH:MM:SS] " when system time is valid (NTP synced or restored
// from RTC by the host firmware), otherwise "[up+12345ms] ".
size_t buildLogPrefix(char *out, size_t n) {
  time_t now = time(nullptr);
  if (now >= 1700000000) { // ~2023-11 sanity: time has been set
    struct tm tm{};
    localtime_r(&now, &tm);
    size_t off = 0;
    if (n > 0) {
      out[off++] = '[';
    }
    size_t w = strftime(out + off, n - off, "%Y-%m-%d %H:%M:%S", &tm);
    if (w == 0) {
      return (size_t)snprintf(out, n, "[up+%lums] ",
                              static_cast<unsigned long>(millis()));
    }
    off += w;
    int rem = snprintf(out + off, n - off, "] ");
    if (rem > 0) {
      off += (size_t)rem;
    }
    return off;
  }
  return (size_t)snprintf(out, n, "[up+%lums] ",
                          static_cast<unsigned long>(millis()));
}

bool tunnelDiagLogTagAllowed(const char *tag) {
#ifdef TUNNEL_DIAG_LOG_ONLY
  if (!tag) {
    return false;
  }
  return strcmp(tag, "SSH") == 0 || strcmp(tag, "CONFIG") == 0 ||
         strcmp(tag, "MAIN") == 0 || strcmp(tag, "MEM") == 0 ||
         strcmp(tag, "RING") == 0;
#else
  (void)tag;
  return true;
#endif
}
} // namespace

void Logger::init() {
  Serial.begin(globalSSHConfig.getDebugConfig().serialBaudRate);
  while (!Serial && millis() < 5000) {
    delay(10);
  }
  Serial.println("Logger initialized");
}

void Logger::log(LogLevel level, const char *tag, const char *message) {
  const DebugConfig &debugConfig = globalSSHConfig.getDebugConfig();
  if (level > debugConfig.minLogLevel) {
    return;
  }
  if (!tunnelDiagLogTagAllowed(tag)) {
    return;
  }

  char prefix[40];
  buildLogPrefix(prefix, sizeof(prefix));
  Serial.printf("%s%s [%s] %s\n", prefix, getLevelString(level), tag, message);
}

void Logger::logf(LogLevel level, const char *tag, const char *format, ...) {
  const DebugConfig &debugConfig = globalSSHConfig.getDebugConfig();
  if (level > debugConfig.minLogLevel) {
    return;
  }

  char buffer[256];
  va_list args;
  va_start(args, format);
  vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);

  log(level, tag, buffer);
}

void Logger::error(const char *tag, const char *message) {
  log(LOG_ERROR, tag, message);
}

void Logger::warn(const char *tag, const char *message) {
  log(LOG_WARN, tag, message);
}

void Logger::info(const char *tag, const char *message) {
  log(LOG_INFO, tag, message);
}

void Logger::debug(const char *tag, const char *message) {
  log(LOG_DEBUG, tag, message);
}

const char *Logger::getLevelString(LogLevel level) {
  switch (level) {
  case LOG_ERROR:
    return "ERROR";
  case LOG_WARN:
    return "WARN ";
  case LOG_INFO:
    return "INFO ";
  case LOG_DEBUG:
    return "DEBUG";
  default:
    return "UNKN ";
  }
}
