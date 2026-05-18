#pragma once
#include <vector>
#include <string>
#include <cstdint>

struct Event
{
    uint64_t start;
    uint64_t stop;

    int appName;
    int serviceName;

    std::string appNameStr;
    std::string serviceNameStr;
    std::string binaryPath; 
};

std::vector<Event> readEvents(const std::string& dbPath);

