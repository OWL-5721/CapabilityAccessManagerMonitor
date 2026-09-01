#include "runtime_config.h"

#include <mutex>

namespace
{
    RuntimeConfig g_config = makeProductionConfig();
    std::mutex g_configMutex;
}

RuntimeConfig makeProductionConfig()
{
    const std::string dataDirectory = "C:\\ProgramData\\CapabilityMonitor";

    return {
        "C:\\ProgramData\\Microsoft\\Windows\\CapabilityAccessManager\\CapabilityAccessManager.db",
        dataDirectory,
        dataDirectory + "\\snapshot.db",
        dataDirectory + "\\alerts.db",
        dataDirectory + "\\baseline.txt",
        dataDirectory + "\\log.txt",
        true,
        10000
    };
}

RuntimeConfig getRuntimeConfig()
{
    std::lock_guard<std::mutex> lock(g_configMutex);
    return g_config;
}

void setRuntimeConfigForTesting(const RuntimeConfig& config)
{
    std::lock_guard<std::mutex> lock(g_configMutex);
    g_config = config;
}

void resetRuntimeConfig()
{
    std::lock_guard<std::mutex> lock(g_configMutex);
    g_config = makeProductionConfig();
}
