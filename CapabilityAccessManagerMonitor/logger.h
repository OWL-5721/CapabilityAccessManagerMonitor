#pragma once

#include <string>

namespace Logger
{
    void Info(
        const std::string& message
    );

    void Error(
        const std::string& message
    );

    void Warning(
        const std::string& message
    );

    void Write(
        const std::string& level,
        const std::string& message
    );
}