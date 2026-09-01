#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct Event
{
    uint64_t start = 0;
    uint64_t stop = 0;
    int appName = 0;
    int serviceName = 0;
    std::string appNameStr;
    std::string serviceNameStr;
    std::string binaryPath;
};

struct AnalyzerResult
{
    std::vector<Event> events;
    bool success = false;
    bool truncated = false;
};

AnalyzerResult readEvents(
    const std::string& dbPath,
    uint64_t minimumStartFiletime,
    int eventLimit
);

std::vector<Event> readEvents(const std::string& dbPath);
