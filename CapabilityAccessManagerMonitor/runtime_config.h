#pragma once

#include <string>

struct RuntimeConfig
{
    std::string sourceDatabasePath;
    std::string dataDirectory;
    std::string snapshotDatabasePath;
    std::string alertDatabasePath;
    std::string baselinePath;
    std::string logPath;
    bool enableUnchangedSourceFastPath = true;
    int eventLimit = 10000;
};

RuntimeConfig makeProductionConfig();
RuntimeConfig getRuntimeConfig();
void setRuntimeConfigForTesting(const RuntimeConfig& config);
void resetRuntimeConfig();
