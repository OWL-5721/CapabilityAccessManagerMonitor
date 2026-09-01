#pragma once

#include "detection_result.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

struct DetectionMetrics
{
    size_t eventCount = 0;
    size_t tightRunEvents = 0;
    size_t peakOneSecondEvents = 0;
    double averageRate = 0.0;
    double baselineRate = 0.0;
    bool baselineAnomaly = false;
    bool periodic = false;
    uint64_t firstEventTime = 0;
    uint64_t lastEventTime = 0;
    std::string type;
};

struct ProcessDetectionContext
{
    DetectionMetrics metrics;
    bool baselineAvailable = false;
    int baselineSamples = 0;
    std::optional<bool> tightLoopOverride;
    std::optional<bool> burstLoopOverride;
    std::optional<bool> steadyLoopOverride;
    std::optional<bool> baselineAnomalyOverride;
    std::optional<bool> periodicOverride;
    std::optional<bool> highActivityOverride;
};

class IDetector
{
public:
    virtual ~IDetector() = default;
    virtual std::optional<DetectorFinding> Analyze(
        const ProcessDetectionContext& context) const = 0;
};

class TightLoopDetector final : public IDetector
{
public:
    std::optional<DetectorFinding> Analyze(
        const ProcessDetectionContext& context) const override;
};

class BurstLoopDetector final : public IDetector
{
public:
    std::optional<DetectorFinding> Analyze(
        const ProcessDetectionContext& context) const override;
};

class SteadyLoopDetector final : public IDetector
{
public:
    std::optional<DetectorFinding> Analyze(
        const ProcessDetectionContext& context) const override;
};

class BaselineAnomalyDetector final : public IDetector
{
public:
    std::optional<DetectorFinding> Analyze(
        const ProcessDetectionContext& context) const override;
};

class PeriodicDetector final : public IDetector
{
public:
    std::optional<DetectorFinding> Analyze(
        const ProcessDetectionContext& context) const override;
};

class HighActivityDetector final : public IDetector
{
public:
    std::optional<DetectorFinding> Analyze(
        const ProcessDetectionContext& context) const override;
};

class DetectionEngine
{
public:
    DetectionEngine();
    explicit DetectionEngine(std::vector<std::unique_ptr<IDetector>> detectors);

    std::vector<DetectorFinding> Analyze(
        const ProcessDetectionContext& context) const;

private:
    std::vector<std::unique_ptr<IDetector>> detectors_;
};

int calculateDetectionConfidence(const ProcessDetectionContext& context);
std::string buildLegacyType(const std::vector<DetectorFinding>& findings);
bool hasFinding(const std::vector<DetectorFinding>& findings, DetectionKind kind);
