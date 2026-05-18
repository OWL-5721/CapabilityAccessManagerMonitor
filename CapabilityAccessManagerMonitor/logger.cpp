#include "logger.h"

#include <fstream>
#include <filesystem>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace
{
    constexpr const char* LOG_DIRECTORY =
        "C:\\ProgramData\\CapabilityMonitor";

    constexpr const char* LOG_FILE =
        "C:\\ProgramData\\CapabilityMonitor\\log.txt";

    std::mutex g_LogMutex;
}

void Logger::Info(
    const std::string& message
)
{
    Write(
        "INFO",
        message
    );
}

void Logger::Error(
    const std::string& message
)
{
    Write(
        "ERROR",
        message
    );
}

void Logger::Warning(
    const std::string& message
)
{
    Write(
        "WARNING",
        message
    );
}

void Logger::Write(
    const std::string& level,
    const std::string& message
)
{
    std::lock_guard<std::mutex> lock(
        g_LogMutex
    );

    try
    {
        std::filesystem::create_directories(
            LOG_DIRECTORY
        );

        std::ofstream logFile(
            LOG_FILE,
            std::ios::app
        );

        if (!logFile.is_open())
        {
            return;
        }

        auto now =
            std::chrono::system_clock::now();

        auto time =
            std::chrono::system_clock::to_time_t(
                now
            );

        std::tm localTime{};

        localtime_s(
            &localTime,
            &time
        );

        std::ostringstream timestamp;

        timestamp
            << std::put_time(
                &localTime,
                "%Y-%m-%d %H:%M:%S"
            );

        logFile
            << "["
            << timestamp.str()
            << "] "
            << "["
            << level
            << "] "
            << message
            << "\n";
    }
    catch (...)
    {
    }
}