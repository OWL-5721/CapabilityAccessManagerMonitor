#include "utils.h"

#include <limits>

bool tryFiletimeToMillis(uint64_t filetime, uint64_t& millis)
{
    if (filetime < FILETIME_UNIX_EPOCH_OFFSET)
    {
        millis = 0;
        return false;
    }

    millis = (filetime - FILETIME_UNIX_EPOCH_OFFSET) / 10000ULL;
    return true;
}

uint64_t filetimeToMillis(uint64_t filetime)
{
    uint64_t millis = 0;
    return tryFiletimeToMillis(filetime, millis) ? millis : 0;
}

uint64_t unixMillisToFiletime(uint64_t millis)
{
    const uint64_t maxMillis =
        (std::numeric_limits<uint64_t>::max() - FILETIME_UNIX_EPOCH_OFFSET) / 10000ULL;

    if (millis > maxMillis)
    {
        return std::numeric_limits<uint64_t>::max();
    }

    return FILETIME_UNIX_EPOCH_OFFSET + millis * 10000ULL;
}
