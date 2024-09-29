#pragma once
#include <spdlog/fmt/fmt.h>
#include <LIEF/logging.hpp>


#define LK_DEBUG(...) lk::log::debug(__VA_ARGS__)
#define LK_INFO(...) lk::log::info(__VA_ARGS__)
#define LK_WARN(...) lk::log::warn(__VA_ARGS__)
#define LK_ERR(...) lk::log::err(__VA_ARGS__)

namespace lk::log {

// ----------------------------------------------------------------------------
// DEBUG
// ----------------------------------------------------------------------------
inline void debug(const char *msg) {
  LIEF::logging::log(LIEF::logging::LEVEL::DEBUG, msg);
}

template <typename... Args>
void debug(const char *fmt, const Args &... args) {
  LIEF::logging::log(LIEF::logging::LEVEL::DEBUG,
    fmt::format(fmt::runtime(fmt), args...)
  );
}

// ----------------------------------------------------------------------------
// INFO
// ----------------------------------------------------------------------------
inline void info(const char *msg) {
  LIEF::logging::log(LIEF::logging::LEVEL::INFO, msg);
}

template <typename... Args>
void info(const char *fmt, const Args &... args) {
  LIEF::logging::log(LIEF::logging::LEVEL::INFO,
    fmt::format(fmt::runtime(fmt), args...)
  );
}

// ----------------------------------------------------------------------------
// WARN
// ----------------------------------------------------------------------------
inline void warn(const char *msg) {
  LIEF::logging::log(LIEF::logging::LEVEL::WARN, msg);
}

template <typename... Args>
void warn(const char *fmt, const Args &... args) {
  LIEF::logging::log(LIEF::logging::LEVEL::WARN,
    fmt::format(fmt::runtime(fmt), args...)
  );
}

// ----------------------------------------------------------------------------
// ERR
// ----------------------------------------------------------------------------
inline void err(const char *msg) {
  LIEF::logging::log(LIEF::logging::LEVEL::ERR, msg);
}

template <typename... Args>
void err(const char *fmt, const Args &... args) {
  LIEF::logging::log(LIEF::logging::LEVEL::ERR,
    fmt::format(fmt::runtime(fmt), args...)
  );
}

// ----------------------------------------------------------------------------
// ERR
// ----------------------------------------------------------------------------
inline void critial(const char *msg) {
  LIEF::logging::log(LIEF::logging::LEVEL::CRITICAL, msg);
}

template <typename... Args>
void critial(const char *fmt, const Args &... args) {
  LIEF::logging::log(LIEF::logging::LEVEL::CRITICAL,
    fmt::format(fmt::runtime(fmt), args...)
  );
}

[[noreturn]] inline void terminate() {
  std::abort();
}

[[noreturn]] inline void fatal_error(const char* msg) {
  critial(msg);
  terminate();
}

template <typename... Args>
[[noreturn]] void fatal_error(const char *fmt, const Args &... args) {
  critial(fmt, args...);
  terminate();
}
}
