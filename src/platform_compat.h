#ifndef TUNNEL_PLATFORM_COMPAT_H
#define TUNNEL_PLATFORM_COMPAT_H

#ifdef TUNNEL_NATIVE_IDF
#include <algorithm>
#include <cctype>
#include <esp_timer.h>
#include <string>

// Preserve the public String API for existing Arduino callers while allowing
// native ESP-IDF projects to use the same tunnel configuration.
class String : public std::string {
public:
  using std::string::string;
  using std::string::operator=;
  using std::string::operator+=;
  String(const std::string &value) : std::string(value) {}
  String substring(size_t from, size_t to = npos) const {
    return substr(from, to == npos ? npos : to - from);
  }
  int indexOf(const char *needle) const {
    auto pos = find(needle);
    return pos == npos ? -1 : static_cast<int>(pos);
  }
  int indexOf(char needle) const {
    auto pos = find(needle);
    return pos == npos ? -1 : static_cast<int>(pos);
  }
  bool startsWith(const char *prefix) const { return rfind(prefix, 0) == 0; }
  bool endsWith(const char *suffix) const {
    size_t size = std::char_traits<char>::length(suffix);
    return length() >= size && compare(length() - size, size, suffix) == 0;
  }
  char charAt(size_t position) const { return at(position); }
  void remove(size_t from, size_t count = npos) { erase(from, count); }
  void replace(const char *oldText, const char *newText) {
    size_t oldSize = std::char_traits<char>::length(oldText);
    if (oldSize == 0) return;
    size_t from = 0;
    while ((from = find(oldText, from)) != npos) {
      std::string::replace(from, oldSize, newText);
      from += std::char_traits<char>::length(newText);
    }
  }
  void trim() {
    auto space = [](unsigned char c) { return std::isspace(c); };
    auto first = std::find_if_not(begin(), end(), space);
    auto last = std::find_if_not(rbegin(), rend(), space).base();
    if (first >= last) { clear(); return; }
    *this = substr(first - begin(), last - first);
  }
  void toLowerCase() {
    std::transform(begin(), end(), begin(),
                   [](unsigned char c) { return std::tolower(c); });
  }
};

inline unsigned long millis() {
  return static_cast<unsigned long>(esp_timer_get_time() / 1000);
}
#else
#include <Arduino.h>
#endif

#endif
