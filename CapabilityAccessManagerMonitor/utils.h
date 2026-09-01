#pragma once

#include <cstdint>

constexpr uint64_t FILETIME_UNIX_EPOCH_OFFSET = 116444736000000000ULL;

bool tryFiletimeToMillis(uint64_t filetime, uint64_t& millis);
uint64_t filetimeToMillis(uint64_t filetime);
uint64_t unixMillisToFiletime(uint64_t millis);
