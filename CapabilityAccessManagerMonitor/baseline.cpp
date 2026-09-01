#include "baseline.h"

#include "logger.h"
#include "runtime_config.h"

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

namespace
{
    constexpr int MAX_BASELINE_SAMPLES = 1000;
    bool g_baselineDirty = false;

    bool parseV2Line(const std::string& line, std::string& process, Baseline& baseline)
    {
        std::istringstream input(line);
        if (!(input >> std::quoted(process) >> baseline.avgRate >> baseline.samples))
        {
            return false;
        }

        input >> std::ws;
        return input.eof();
    }

    bool parseLegacyLine(const std::string& line, std::string& process, Baseline& baseline)
    {
        const size_t samplesStart = line.find_last_not_of(" \t", line.size() - 1);
        if (samplesStart == std::string::npos)
        {
            return false;
        }
        const size_t samplesTokenStart = line.find_last_of(" \t", samplesStart);
        if (samplesTokenStart == std::string::npos)
        {
            return false;
        }

        size_t rateEnd = line.find_last_not_of(" \t", samplesTokenStart);
        if (rateEnd == std::string::npos)
        {
            return false;
        }

        const size_t rateSeparator = line.find_last_of(" \t", rateEnd);
        if (rateSeparator == std::string::npos)
        {
            return false;
        }

        process = line.substr(0, rateSeparator);
        const std::string rateText = line.substr(rateSeparator + 1, rateEnd - rateSeparator);
        const std::string samplesText = line.substr(samplesTokenStart + 1, samplesStart - samplesTokenStart);

        try
        {
            size_t rateParsed = 0;
            size_t samplesParsed = 0;
            baseline.avgRate = std::stod(rateText, &rateParsed);
            baseline.samples = std::stoi(samplesText, &samplesParsed);
            return rateParsed == rateText.size() && samplesParsed == samplesText.size();
        }
        catch (...)
        {
            return false;
        }
    }

    bool isValid(const std::string& process, const Baseline& baseline)
    {
        return !process.empty() && std::isfinite(baseline.avgRate) &&
            baseline.avgRate >= 0.0 && baseline.samples >= 0;
    }
}

std::unordered_map<std::string, Baseline> baselineDB;

bool loadBaseline()
{
    baselineDB.clear();
    g_baselineDirty = false;

    std::ifstream input(getRuntimeConfig().baselinePath);
    if (!input)
    {
        Logger::Info("[BASELINE] No baseline file found; starting fresh");
        return true;
    }

    std::string line;
    bool v2 = false;
    bool legacy = true;
    size_t rejected = 0;

    if (std::getline(input, line) && line == "CAPABILITY_MONITOR_BASELINE_V2")
    {
        v2 = true;
        legacy = false;
    }
    else
    {
        input.clear();
        input.seekg(0);
    }

    while (std::getline(input, line))
    {
        if (line.empty())
        {
            continue;
        }

        std::string process;
        Baseline baseline;
        const bool parsed = v2
            ? parseV2Line(line, process, baseline)
            : parseLegacyLine(line, process, baseline);

        if (!parsed || !isValid(process, baseline))
        {
            ++rejected;
            continue;
        }

        baseline.samples = std::min(baseline.samples, MAX_BASELINE_SAMPLES);
        baselineDB[process] = baseline;
    }

    if (legacy && !baselineDB.empty())
    {
        g_baselineDirty = true;
        Logger::Info("[BASELINE] Legacy baseline loaded; v2 migration scheduled");
    }

    if (rejected > 0)
    {
        Logger::Warning("[BASELINE] Ignored " + std::to_string(rejected) + " malformed entries");
    }

    Logger::Info("[BASELINE] Loaded " + std::to_string(baselineDB.size()) + " entries");
    return true;
}

bool saveBaseline()
{
    if (!g_baselineDirty)
    {
        return true;
    }

    const auto config = getRuntimeConfig();
    std::error_code error;
    std::filesystem::create_directories(config.dataDirectory, error);
    if (error)
    {
        Logger::Error("[BASELINE] Cannot create data directory: " + error.message());
        return false;
    }

    const std::filesystem::path destination(config.baselinePath);
    const std::filesystem::path temporary = destination.string() + ".tmp";

    {
        std::ofstream output(temporary, std::ios::trunc);
        if (!output)
        {
            Logger::Error("[BASELINE] Cannot write temporary baseline: " + temporary.string());
            return false;
        }

        output << "CAPABILITY_MONITOR_BASELINE_V2\n";
        output << std::setprecision(std::numeric_limits<double>::max_digits10);
        for (const auto& [process, baseline] : baselineDB)
        {
            output << std::quoted(process) << ' '
                << baseline.avgRate << ' ' << baseline.samples << '\n';
        }

        output.flush();
        if (!output)
        {
            Logger::Error("[BASELINE] Failed while writing baseline: " + temporary.string());
            return false;
        }
    }

    std::filesystem::remove(destination, error);
    error.clear();
    std::filesystem::rename(temporary, destination, error);
    if (error)
    {
        Logger::Error("[BASELINE] Atomic replace failed: " + error.message());
        std::filesystem::remove(temporary, error);
        return false;
    }

    g_baselineDirty = false;
    return true;
}

void updateBaseline(const std::string& process, double avgRate)
{
    if (!std::isfinite(avgRate) || avgRate < 0.0)
    {
        return;
    }

    auto& baseline = baselineDB[process];
    const int weight = std::min(baseline.samples, MAX_BASELINE_SAMPLES);
    baseline.avgRate = (baseline.avgRate * weight + avgRate) /
        static_cast<double>(weight + 1);
    baseline.samples = std::min(weight + 1, MAX_BASELINE_SAMPLES);
    g_baselineDirty = true;
}

bool isBaselineDirty()
{
    return g_baselineDirty;
}

void clearBaselineForTesting()
{
    baselineDB.clear();
    g_baselineDirty = false;
}
