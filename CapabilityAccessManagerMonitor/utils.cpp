#include "utils.h"

uint64_t filetimeToMillis(uint64_t ft) {
    return (ft - 116444736000000000ULL) / 10000ULL;
}