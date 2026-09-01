#include "detector_pipeline.h"

#include <algorithm>
#include <cmath>
#include <utility>

namespace
{
    constexpr size_t TIGHT_LOOP_MIN = 15;
    constexpr size_t BURST_RATE_MIN = 50;
    constexpr double STEADY_RATE_MIN = 15.0;
    constexpr double BASELINE_MULT = 2.0;
    constexpr size_t HIGH_ACTIVITY_MIN = 50;

    constexpr int TIGHT_LOOP_SCORE = 30;
    constexpr int BURST_LOOP_SCORE = 30;
    constexpr int STEADY_LOOP_SCORE = 25;
    constexpr int BASELINE_ANOMALY_SCORE = 25;
    constexpr int PERIODIC_SCORE = 10;
    constexpr int HIGH_ACTIVITY_SCORE = 10;

    std::optional<DetectorFinding> makeFinding(
        bool triggered,
        DetectionKind kind,
        int score,
        int confidence,
        const char* code,
        double value,
        double threshold,
        const char* unit,
        const char* explanation)
    {
        if (!triggered)
        {
            return std::nullopt;
        }

        DetectorFinding finding;
        finding.kind = kind;
        finding.scoreContribution = score;
        finding.confidence = confidence;
        finding.evidence.push_back({ code, value, threshold, unit, explanation });
        return finding;
    }
}

int calculateDetectionConfidence(const ProcessDetectionContext& context)
{
    int confidence = 45;
    confidence += static_cast<int>(
        std::min<size_t>(context.metrics.eventCount, 100) * 30 / 100);
    if (context.baselineAvailable)
    {
        confidence += std::min(context.baselineSamples, 100) * 20 / 100;
    }
    else
    {
        confidence -= 10;
    }
    if (context.metrics.eventCount < 20)
    {
        confidence -= 10;
    }
    return std::clamp(confidence, 0, 100);
}

std::optional<DetectorFinding> TightLoopDetector::Analyze(
    const ProcessDetectionContext& context) const
{
    return makeFinding(
        context.tightLoopOverride.value_or(
            context.metrics.tightRunEvents >= TIGHT_LOOP_MIN),
        DetectionKind::TightLoop,
        TIGHT_LOOP_SCORE,
        calculateDetectionConfidence(context),
        "tight_run_events",
        static_cast<double>(context.metrics.tightRunEvents),
        static_cast<double>(TIGHT_LOOP_MIN),
        "events",
        "Consecutive events were separated by less than 50 milliseconds");
}

std::optional<DetectorFinding> BurstLoopDetector::Analyze(
    const ProcessDetectionContext& context) const
{
    return makeFinding(
        context.burstLoopOverride.value_or(
            context.metrics.peakOneSecondEvents > BURST_RATE_MIN),
        DetectionKind::BurstLoop,
        BURST_LOOP_SCORE,
        calculateDetectionConfidence(context),
        "peak_one_second_events",
        static_cast<double>(context.metrics.peakOneSecondEvents),
        static_cast<double>(BURST_RATE_MIN),
        "events/second",
        "Peak activity exceeded the one-second burst threshold");
}

std::optional<DetectorFinding> SteadyLoopDetector::Analyze(
    const ProcessDetectionContext& context) const
{
    const double averageRate = std::isfinite(context.metrics.averageRate) &&
        context.metrics.averageRate >= 0.0 ? context.metrics.averageRate : 0.0;
    return makeFinding(
        context.steadyLoopOverride.value_or(averageRate > STEADY_RATE_MIN),
        DetectionKind::SteadyLoop,
        STEADY_LOOP_SCORE,
        calculateDetectionConfidence(context),
        "average_rate",
        averageRate,
        STEADY_RATE_MIN,
        "events/second",
        "Average activity exceeded the steady-rate threshold");
}

std::optional<DetectorFinding> BaselineAnomalyDetector::Analyze(
    const ProcessDetectionContext& context) const
{
    const double averageRate = std::isfinite(context.metrics.averageRate) &&
        context.metrics.averageRate >= 0.0 ? context.metrics.averageRate : 0.0;
    const double baselineRate = std::isfinite(context.metrics.baselineRate) &&
        context.metrics.baselineRate >= 0.0 ? context.metrics.baselineRate : 0.0;
    const bool triggered = context.baselineAnomalyOverride.value_or(
        context.metrics.baselineAnomaly && baselineRate > 0.0 &&
        averageRate > baselineRate * BASELINE_MULT);
    return makeFinding(
        triggered,
        DetectionKind::BaselineAnomaly,
        BASELINE_ANOMALY_SCORE,
        calculateDetectionConfidence(context),
        "baseline_ratio",
        baselineRate > 0.0 ? averageRate / baselineRate : 0.0,
        BASELINE_MULT,
        "ratio",
        "Current activity exceeded twice the historical baseline");
}

std::optional<DetectorFinding> PeriodicDetector::Analyze(
    const ProcessDetectionContext& context) const
{
    return makeFinding(
        context.periodicOverride.value_or(context.metrics.periodic),
        DetectionKind::Periodic,
        PERIODIC_SCORE,
        calculateDetectionConfidence(context),
        "periodic_timing",
        1.0,
        1.0,
        "boolean",
        "Inter-event timing was highly regular");
}

std::optional<DetectorFinding> HighActivityDetector::Analyze(
    const ProcessDetectionContext& context) const
{
    return makeFinding(
        context.highActivityOverride.value_or(
            context.metrics.eventCount > HIGH_ACTIVITY_MIN),
        DetectionKind::HighActivity,
        HIGH_ACTIVITY_SCORE,
        calculateDetectionConfidence(context),
        "event_count",
        static_cast<double>(context.metrics.eventCount),
        static_cast<double>(HIGH_ACTIVITY_MIN),
        "events",
        "Event count exceeded the high-activity threshold");
}

DetectionEngine::DetectionEngine()
{
    detectors_.reserve(6);
    detectors_.push_back(std::make_unique<TightLoopDetector>());
    detectors_.push_back(std::make_unique<BurstLoopDetector>());
    detectors_.push_back(std::make_unique<SteadyLoopDetector>());
    detectors_.push_back(std::make_unique<BaselineAnomalyDetector>());
    detectors_.push_back(std::make_unique<PeriodicDetector>());
    detectors_.push_back(std::make_unique<HighActivityDetector>());
}

DetectionEngine::DetectionEngine(std::vector<std::unique_ptr<IDetector>> detectors)
    : detectors_(std::move(detectors))
{
}

std::vector<DetectorFinding> DetectionEngine::Analyze(
    const ProcessDetectionContext& context) const
{
    std::vector<DetectorFinding> findings;
    findings.reserve(detectors_.size());
    for (const auto& detector : detectors_)
    {
        if (!detector)
        {
            continue;
        }
        auto finding = detector->Analyze(context);
        if (finding)
        {
            findings.push_back(std::move(*finding));
        }
    }
    return findings;
}

std::string buildLegacyType(const std::vector<DetectorFinding>& findings)
{
    std::string type;
    for (const auto& finding : findings)
    {
        if (!type.empty())
        {
            type += ' ';
        }
        type += detectionKindLabel(finding.kind);
    }
    return type;
}

bool hasFinding(const std::vector<DetectorFinding>& findings, DetectionKind kind)
{
    return std::any_of(
        findings.begin(),
        findings.end(),
        [kind](const DetectorFinding& finding) { return finding.kind == kind; });
}
