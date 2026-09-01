#pragma once

#include "detection_result.h"
#include "detector_pipeline.h"

#include <cstddef>
#include <vector>

constexpr int RISK_SCORING_VERSION = 1;

struct RiskScoringInput
{
    bool tightLoop = false;
    bool burstLoop = false;
    bool steadyLoop = false;
    bool baselineAnomaly = false;
    bool periodic = false;
    bool highActivity = false;
    size_t eventCount = 0;
    size_t peakOneSecondEvents = 0;
    size_t tightRunEvents = 0;
    double averageRate = 0.0;
    double baselineRate = 0.0;
    bool baselineAvailable = false;
    int baselineSamples = 0;
};

DetectionResult scoreDetection(const RiskScoringInput& input);
DetectionResult scoreFindings(
    const ProcessDetectionContext& context,
    std::vector<DetectorFinding> findings
);
Severity severityForRiskScore(int riskScore);
