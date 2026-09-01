#include "logger.h"

#include "runtime_config.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>

namespace
{
    std::mutex g_LogMutex;
}

void Logger::Info(const std::string& message)
{
    Write("INFO", message);
}

void Logger::Error(const std::string& message)
{
    Write("ERROR", message);
}

void Logger::Warning(const std::string& message)
{
    Write("WARNING", message);
}

void Logger::Write(const std::string& level, const std::string& message)
{
    std::lock_guard<std::mutex> lock(g_LogMutex);

    try
    {
        const auto config = getRuntimeConfig();
        std::filesystem::create_directories(config.dataDirectory);
        std::ofstream logFile(config.logPath, std::ios::app);
        if (!logFile)
        {
            return;
        }

        const auto now = std::chrono::system_clock::now();
        const auto time = std::chrono::system_clock::to_time_t(now);
        std::tm localTime{};
        localtime_s(&localTime, &time);

        logFile << '[' << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S")
            << "] [" << level << "] " << message << '\n';
    }
    catch (...)
    {
    }
}
