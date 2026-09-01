#include "detector.h"

#include "alert_manager.h"
#include "baseline.h"
#include "logger.h"
#include "risk_scoring.h"
#include "runtime_config.h"
#include "snapshot.h"
#include "utils.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <sstream>
#include <unordered_map>

namespace
{
    constexpr uint64_t WINDOW_MS = 28'800'000ULL;
    constexpr uint64_t FUTURE_TOLERANCE_MS = 60'000ULL;
    constexpr uint64_t TIGHT_LOOP_GAP = 50ULL;
    constexpr size_t TIGHT_LOOP_MIN = 15;
    constexpr size_t BURST_RATE_MIN = 50;
    constexpr double STEADY_RATE_MIN = 15.0;
    constexpr double BASELINE_MULT = 2.0;
    constexpr double PERIODIC_COV = 0.10;
    constexpr uint64_t PERIODIC_MIN_MS = 10ULL;
    constexpr size_t MIN_EVENTS = 10;
    constexpr size_t MIN_EVENTS_FULL = 10;

    struct SourceState
    {
        std::filesystem::file_time_type databaseWriteTime{};
        uintmax_t databaseSize = 0;
        std::filesystem::file_time_type walWriteTime{};
        uintmax_t walSize = 0;
        bool hasWal = false;
        bool valid = false;
    };

    SourceState g_lastSourceState;

    std::string getProcessName(const std::string& path)
    {
        const size_t position = path.find_last_of("\\/");
        return position == std::string::npos ? path : path.substr(position + 1);
    }

    uint64_t currentUnixMillis()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }

    bool readSourceState(const std::string& databasePath, SourceState& state)
    {
        std::error_code error;
        const std::filesystem::path database(databasePath);
        if (!std::filesystem::is_regular_file(database, error) || error)
        {
            return false;
        }

        state.databaseWriteTime = std::filesystem::last_write_time(database, error);
        if (error) return false;
        state.databaseSize = std::filesystem::file_size(database, error);
        if (error) return false;

        const std::filesystem::path wal(databasePath + "-wal");
        error.clear();
        state.hasWal = std::filesystem::is_regular_file(wal, error) && !error;
        if (state.hasWal)
        {
            state.walWriteTime = std::filesystem::last_write_time(wal, error);
            if (error) return false;
            state.walSize = std::filesystem::file_size(wal, error);
            if (error) return false;
        }

        state.valid = true;
        return true;
    }

    bool sameSourceState(const SourceState& left, const SourceState& right)
    {
        return left.valid && right.valid &&
            left.databaseWriteTime == right.databaseWriteTime &&
            left.databaseSize == right.databaseSize &&
            left.hasWal == right.hasWal &&
            (!left.hasWal || (left.walWriteTime == right.walWriteTime && left.walSize == right.walSize));
    }
}

DetectionMetrics analyzeProcessTimes(
    std::vector<uint64_t> times,
    uint64_t nowMillis,
    double baselineRate)
{
    DetectionMetrics metrics;
    metrics.baselineRate = baselineRate;

    if (times.size() < MIN_EVENTS_FULL)
    {
        return metrics;
    }

    std::sort(times.begin(), times.end());
    const uint64_t cutoff = nowMillis > WINDOW_MS ? nowMillis - WINDOW_MS : 0;
    const uint64_t futureLimit = nowMillis > UINT64_MAX - FUTURE_TOLERANCE_MS
        ? UINT64_MAX
        : nowMillis + FUTURE_TOLERANCE_MS;

    const auto begin = std::lower_bound(times.begin(), times.end(), cutoff);
    const auto end = std::upper_bound(begin, times.end(), futureLimit);
    times.erase(end, times.end());
    times.erase(times.begin(), begin);

    metrics.eventCount = times.size();
    if (!times.empty())
    {
        metrics.firstEventTime = times.front();
        metrics.lastEventTime = times.back();
    }
    if (times.size() < MIN_EVENTS)
    {
        return metrics;
    }

    size_t currentTightRun = 1;
    metrics.tightRunEvents = 1;
    size_t left = 0;
    double deltaSum = 0.0;
    double deltaSquareSum = 0.0;

    for (size_t right = 1; right < times.size(); ++right)
    {
        const uint64_t delta = times[right] - times[right - 1];
        if (delta < TIGHT_LOOP_GAP)
        {
            ++currentTightRun;
            metrics.tightRunEvents = std::max(metrics.tightRunEvents, currentTightRun);
        }
        else
        {
            currentTightRun = 1;
        }

        const double deltaValue = static_cast<double>(delta);
        deltaSum += deltaValue;
        deltaSquareSum += deltaValue * deltaValue;
    }

    for (size_t right = 0; right < times.size(); ++right)
    {
        while (left < right && times[right] - times[left] >= 1000ULL)
        {
            ++left;
        }
        metrics.peakOneSecondEvents = std::max(metrics.peakOneSecondEvents, right - left + 1);
    }

    const uint64_t duration = times.back() - times.front();
    if (duration > 0)
    {
        metrics.averageRate = static_cast<double>(times.size() - 1) * 1000.0 /
            static_cast<double>(duration);
    }

    metrics.baselineAnomaly = baselineRate > 0.0 &&
        metrics.averageRate > baselineRate * BASELINE_MULT;

    const size_t deltaCount = times.size() - 1;
    if (deltaCount > 0)
    {
        const double mean = deltaSum / static_cast<double>(deltaCount);
        const double variance = std::max(
            0.0,
            deltaSquareSum / static_cast<double>(deltaCount) - mean * mean);
        const double coefficient = mean > 0.0 ? std::sqrt(variance) / mean : 0.0;
        metrics.periodic = mean > static_cast<double>(PERIODIC_MIN_MS) &&
            coefficient < PERIODIC_COV;
    }

    ProcessDetectionContext context;
    context.metrics = metrics;
    DetectionEngine engine;
    metrics.type = buildLegacyType(engine.Analyze(context));

    return metrics;
}

DetectionResult buildDetectionResult(
    const std::string& processPath,
    const DetectionMetrics& metrics,
    bool baselineAvailable,
    int baselineSamples)
{
    ProcessDetectionContext context;
    context.metrics = metrics;
    context.baselineAvailable = baselineAvailable;
    context.baselineSamples = baselineSamples;

    DetectionEngine engine;
    DetectionResult result = scoreFindings(context, engine.Analyze(context));
    result.processPath = processPath;
    result.process = getProcessName(processPath);
    result.firstEventTime = metrics.firstEventTime;
    result.lastEventTime = metrics.lastEventTime;
    return result;
}

void detectLoops(const std::vector<Event>& events)
{
    std::unordered_map<std::string, std::vector<uint64_t>> processTimes;
    processTimes.reserve(events.size() / MIN_EVENTS_FULL + 1);
    size_t invalidTimestamps = 0;

    for (const auto& event : events)
    {
        uint64_t timestamp = 0;
        if (!tryFiletimeToMillis(event.start, timestamp) || event.binaryPath.empty() ||
            event.binaryPath == "UNKNOWN")
        {
            ++invalidTimestamps;
            continue;
        }
        processTimes[event.binaryPath].push_back(timestamp);
    }

    const uint64_t nowMillis = currentUnixMillis();
    for (auto& [process, times] : processTimes)
    {
        const auto baseline = baselineDB.find(process);
        const bool baselineAvailable = baseline != baselineDB.end();
        const double baselineRate = baselineAvailable ? baseline->second.avgRate : 0.0;
        const int baselineSamples = baselineAvailable ? baseline->second.samples : 0;
        const DetectionMetrics metrics = analyzeProcessTimes(std::move(times), nowMillis, baselineRate);
        if (metrics.eventCount < MIN_EVENTS)
        {
            continue;
        }

        const DetectionResult detection = buildDetectionResult(
            process, metrics, baselineAvailable, baselineSamples);
        if (!detection.findings.empty())
        {
            handleAlert(detection);
            std::ostringstream message;
            message << "[DETECTOR] " << detection.process
                << " | " << detection.legacyType
                << " | score=" << detection.riskScore
                << " severity=" << severityCode(detection.severity)
                << " confidence=" << detection.confidence
                << " peak=" << detection.peakOneSecondEvents
                << " avg=" << detection.averageRate
                << " baseline=" << detection.baselineRate
                << " count=" << detection.eventCount;
            Logger::Warning(message.str());
        }

        if (!hasFinding(detection.findings, DetectionKind::BaselineAnomaly))
        {
            updateBaseline(process, metrics.averageRate);
        }
    }

    if (invalidTimestamps > 0)
    {
        Logger::Warning("[DETECTOR] Ignored " + std::to_string(invalidTimestamps) +
            " invalid events");
    }
}

bool RunDetector()
{
    const auto config = getRuntimeConfig();
    SourceState currentState;
    const bool hasSourceState = readSourceState(config.sourceDatabasePath, currentState);
    if (config.enableUnchangedSourceFastPath && hasSourceState &&
        sameSourceState(currentState, g_lastSourceState))
    {
        return true;
    }

    if (!backupDatabase(config.sourceDatabasePath, config.snapshotDatabasePath))
    {
        Logger::Error("Failed to backup CapabilityAccessManager DB");
        return false;
    }

    const uint64_t nowMillis = currentUnixMillis();
    const uint64_t cutoffMillis = nowMillis > WINDOW_MS ? nowMillis - WINDOW_MS : 0;
    const AnalyzerResult result = readEvents(
        config.snapshotDatabasePath,
        unixMillisToFiletime(cutoffMillis),
        config.eventLimit);

    if (!result.success)
    {
        return false;
    }

    detectLoops(result.events);
    if (hasSourceState)
    {
        g_lastSourceState = currentState;
    }
    return true;
}

void resetDetectorSourceState()
{
    g_lastSourceState = {};
}
