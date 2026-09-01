#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class DetectionKind
{
    TightLoop,
    BurstLoop,
    SteadyLoop,
    BaselineAnomaly,
    Periodic,
    HighActivity
};

enum class Severity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
};

struct EvidenceItem
{
    std::string code;
    double value = 0.0;
    double threshold = 0.0;
    std::string unit;
    std::string explanation;
};

struct DetectorFinding
{
    DetectionKind kind = DetectionKind::HighActivity;
    int scoreContribution = 0;
    int confidence = 0;
    std::vector<EvidenceItem> evidence;
};

struct DetectionResult
{
    std::string processPath;
    std::string process;
    std::string legacyType;
    int riskScore = 0;
    Severity severity = Severity::Informational;
    int confidence = 0;
    int scoringVersion = 1;
    size_t eventCount = 0;
    size_t peakOneSecondEvents = 0;
    double averageRate = 0.0;
    double baselineRate = 0.0;
    uint64_t firstEventTime = 0;
    uint64_t lastEventTime = 0;
    std::vector<DetectorFinding> findings;
};

const char* detectionKindCode(DetectionKind kind);
const char* detectionKindLabel(DetectionKind kind);
const char* severityCode(Severity severity);
std::string serializeEvidenceJson(const DetectionResult& result);
