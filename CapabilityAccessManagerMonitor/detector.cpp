#include "detector.h"
#include "baseline.h"
#include "alert_manager.h"
#include "snapshot.h"
#include "logger.h"
#include "utils.h"

#include <unordered_map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <cmath>


static constexpr uint64_t WINDOW_MS = 28'800'000ULL; // 8 hours
static constexpr uint64_t TIGHT_LOOP_GAP = 50;            // ms
static constexpr int      TIGHT_LOOP_MIN = 15;            // consecutive events
static constexpr int      BURST_RATE_MIN = 50;            // events/sec
static constexpr double   STEADY_RATE_MIN = 15.0;          // events/sec avg
static constexpr double   BASELINE_MULT = 2.0;           // anomaly threshold
static constexpr double   PERIODIC_COV = 0.10;          // coeff of variation
static constexpr uint64_t PERIODIC_MIN_MS = 10;            // min mean gap (ms)
static constexpr size_t   MIN_EVENTS = 10;
static constexpr size_t   MIN_EVENTS_FULL = 20;

static std::string getProcessName(const std::string& path)
{
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos)
        return path;
    return path.substr(pos + 1);
}

void detectLoops(const std::vector<Event>& events)
{
    std::unordered_map<std::string, std::vector<uint64_t>> processTimes;

    loadBaseline();

    for (const auto& e : events)
    {
        uint64_t t = filetimeToMillis(e.start);
        processTimes[e.binaryPath].push_back(t);
    }

    for (auto& pair : processTimes)
    {
        const std::string& process = pair.first;
        std::vector<uint64_t>& times = pair.second;

        if (times.size() < MIN_EVENTS_FULL)
            continue;

        std::sort(times.begin(), times.end());

        {
            uint64_t windowStart = times.back() - WINDOW_MS;

            auto it = std::lower_bound(
                times.begin(), times.end(), windowStart
            );
            times.erase(times.begin(), it);
        }

        if (times.size() < MIN_EVENTS)
            continue;

        int burstCount = 0;
        int maxBurst = 0;

        for (size_t i = 1; i < times.size(); ++i)
        {
            uint64_t delta = times[i] - times[i - 1];

            if (delta < TIGHT_LOOP_GAP)
            {
                ++burstCount;
            }
            else
            {
                maxBurst = std::max(maxBurst, burstCount);
                burstCount = 0;
            }
        }
        maxBurst = std::max(maxBurst, burstCount);

        int    maxRate = 0;
        size_t left = 0;

        for (size_t right = 0; right < times.size(); ++right)
        {
            while (times[right] - times[left] > 1000ULL)
                ++left;

            int windowCount = static_cast<int>(right - left + 1);
            maxRate = std::max(maxRate, windowCount);
        }

        uint64_t duration = times.back() - times.front();
        double avgRate = (duration > 0)
            ? static_cast<double>(times.size()) * 1000.0
            / static_cast<double>(duration)
            : 0.0;

        double baselineRate = 0.0;
        bool   baselineAnomaly = false;

        if (baselineDB.count(process))
        {
            baselineRate = baselineDB[process].avgRate;
            baselineAnomaly = (baselineRate > 0.0 &&
                avgRate > baselineRate * BASELINE_MULT);
        }

        bool isPeriodic = false;

        if (times.size() > 5)
        {
            std::vector<double> deltas;
            deltas.reserve(times.size() - 1);

            for (size_t i = 1; i < times.size(); ++i)
                deltas.push_back(
                    static_cast<double>(times[i] - times[i - 1])
                );

            double mean = 0.0;
            for (double d : deltas) mean += d;
            mean /= static_cast<double>(deltas.size());

            double variance = 0.0;
            for (double d : deltas)
                variance += (d - mean) * (d - mean);
            variance /= static_cast<double>(deltas.size());

            double stddev = std::sqrt(variance);

            isPeriodic = (mean > static_cast<double>(PERIODIC_MIN_MS) &&
                stddev / mean < PERIODIC_COV);
        }

        std::string loopType;

        if (maxBurst > TIGHT_LOOP_MIN)  loopType += "TIGHT LOOP ";
        if (maxRate > BURST_RATE_MIN)  loopType += "BURST LOOP ";
        if (avgRate > STEADY_RATE_MIN) loopType += "STEADY LOOP ";
        if (baselineAnomaly)              loopType += "BASELINE ANOMALY ";
        if (isPeriodic)                   loopType += "PERIODIC ";
        if (times.size() > 50)           loopType += "HIGH ACTIVITY ";

        while (!loopType.empty() && std::isspace(
            static_cast<unsigned char>(loopType.back())))
        {
            loopType.pop_back();
        }

        std::cout
            << "\n[Process] " << getProcessName(process) << "\n"
            << "[Debug]"
            << "  burst=" << maxBurst
            << "  rate=" << maxRate
            << "  avg=" << avgRate
            << "  baseline=" << baselineRate
            << "  count=" << times.size()
            << "\n";

        if (!loopType.empty())
            std::cout << "[Type] " << loopType << "\n";

        if (!loopType.empty())
        {
            handleAlert(getProcessName(process), loopType);

            std::cout
                << "\n[ALERT] " << loopType << "\n"
                << "Process  : " << getProcessName(process) << "\n"
                << "Rate     : " << maxRate << " events/sec\n"
                << "AvgRate  : " << avgRate << " events/sec\n";
        }

        updateBaseline(process, avgRate);
    }

    saveBaseline();
}

void RunDetector()
{
    const std::string sourceDB =
        "C:\\ProgramData\\Microsoft\\Windows\\"
        "CapabilityAccessManager\\CapabilityAccessManager.db";

    const std::string snapshotDB =
        "C:\\ProgramData\\CapabilityMonitor\\snapshot.db";

    if (backupDatabase(sourceDB, snapshotDB))
    {
        auto events = readEvents(snapshotDB);
        detectLoops(events);
    }
    else
    {
        Logger::Error("Failed to backup CapabilityAccessManager DB");
    }
}