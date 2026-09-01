#include "risk_scoring.h"

#include <algorithm>
#include <cmath>
#include <utility>

namespace
{
    double sanitizeRate(double value)
    {
        return std::isfinite(value) && value >= 0.0 ? value : 0.0;
    }
}

Severity severityForRiskScore(int riskScore)
{
    if (riskScore >= 80) return Severity::Critical;
    if (riskScore >= 60) return Severity::High;
    if (riskScore >= 40) return Severity::Medium;
    if (riskScore >= 20) return Severity::Low;
    return Severity::Informational;
}

DetectionResult scoreFindings(
    const ProcessDetectionContext& context,
    std::vector<DetectorFinding> findings)
{
    DetectionResult result;
    result.scoringVersion = RISK_SCORING_VERSION;
    result.eventCount = context.metrics.eventCount;
    result.peakOneSecondEvents = context.metrics.peakOneSecondEvents;
    result.averageRate = sanitizeRate(context.metrics.averageRate);
    result.baselineRate = sanitizeRate(context.metrics.baselineRate);
    result.findings = std::move(findings);
    result.legacyType = buildLegacyType(result.findings);

    int totalScore = 0;
    int weightedConfidence = 0;
    int totalWeight = 0;
    for (const auto& finding : result.findings)
    {
        totalScore += finding.scoreContribution;
        weightedConfidence += finding.confidence * finding.scoreContribution;
        totalWeight += finding.scoreContribution;
    }

    result.riskScore = std::clamp(totalScore, 0, 100);
    result.severity = severityForRiskScore(result.riskScore);
    result.confidence = totalWeight > 0 ? weightedConfidence / totalWeight : 0;
    return result;
}

DetectionResult scoreDetection(const RiskScoringInput& input)
{
    ProcessDetectionContext context;
    context.metrics.eventCount = input.eventCount;
    context.metrics.peakOneSecondEvents = input.peakOneSecondEvents;
    context.metrics.tightRunEvents = input.tightRunEvents;
    context.metrics.averageRate = input.averageRate;
    context.metrics.baselineRate = input.baselineRate;
    context.metrics.baselineAnomaly = input.baselineAnomaly;
    context.metrics.periodic = input.periodic;
    context.baselineAvailable = input.baselineAvailable;
    context.baselineSamples = input.baselineSamples;
    context.tightLoopOverride = input.tightLoop;
    context.burstLoopOverride = input.burstLoop;
    context.steadyLoopOverride = input.steadyLoop;
    context.baselineAnomalyOverride = input.baselineAnomaly;
    context.periodicOverride = input.periodic;
    context.highActivityOverride = input.highActivity;

    DetectionEngine engine;
    return scoreFindings(context, engine.Analyze(context));
}
