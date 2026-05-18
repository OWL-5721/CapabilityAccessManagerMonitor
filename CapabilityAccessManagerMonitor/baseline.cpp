#include "baseline.h"
#include <fstream>
#include <filesystem>
#include "logger.h"

static const std::string BASELINE_DIR =
"C:\\ProgramData\\CapabilityMonitor";

static const std::string BASELINE_PATH =
BASELINE_DIR + "\\baseline.txt";

std::unordered_map<std::string, Baseline> baselineDB;

void loadBaseline()
{
    std::ifstream in(BASELINE_PATH);

    if (!in)
    {
        Logger::Info("[BASELINE] No baseline file found — starting fresh");
        return;
    }

    std::string process;
    double      rate = 0.0;
    int         samples = 0;

    while (in >> process >> rate >> samples)
    {
        baselineDB[process] = { rate, samples };
    }

    Logger::Info(
        "[BASELINE] Loaded "
        + std::to_string(baselineDB.size())
        + " entries"
    );
}

void saveBaseline()
{
    std::filesystem::create_directories(BASELINE_DIR);

    std::ofstream out(BASELINE_PATH);

    if (!out)
    {
        Logger::Error("[BASELINE] Cannot write baseline file: " + BASELINE_PATH);
        return;
    }

    for (const auto& pair : baselineDB)
    {
        out << pair.first << " "
            << pair.second.avgRate << " "
            << pair.second.samples << "\n";
    }
}

void updateBaseline(const std::string& process, double avgRate)
{
    auto& b = baselineDB[process];

    // Running average: new_avg = (old_avg * n + new_value) / (n + 1)
    b.avgRate = (b.avgRate * b.samples + avgRate)
        / static_cast<double>(b.samples + 1);

    b.samples++;
}