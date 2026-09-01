#include "detection_result.h"

#include <cmath>
#include <iomanip>
#include <sstream>

namespace
{
    std::string escapeJson(const std::string& value)
    {
        std::ostringstream output;
        for (const unsigned char character : value)
        {
            switch (character)
            {
            case '\"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20)
                {
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(character) << std::dec;
                }
                else
                {
                    output << static_cast<char>(character);
                }
            }
        }
        return output.str();
    }

    double finiteValue(double value)
    {
        return std::isfinite(value) ? value : 0.0;
    }
}

const char* detectionKindCode(DetectionKind kind)
{
    switch (kind)
    {
    case DetectionKind::TightLoop: return "tight_loop";
    case DetectionKind::BurstLoop: return "burst_loop";
    case DetectionKind::SteadyLoop: return "steady_loop";
    case DetectionKind::BaselineAnomaly: return "baseline_anomaly";
    case DetectionKind::Periodic: return "periodic";
    case DetectionKind::HighActivity: return "high_activity";
    }
    return "unknown";
}

const char* detectionKindLabel(DetectionKind kind)
{
    switch (kind)
    {
    case DetectionKind::TightLoop: return "TIGHT LOOP";
    case DetectionKind::BurstLoop: return "BURST LOOP";
    case DetectionKind::SteadyLoop: return "STEADY LOOP";
    case DetectionKind::BaselineAnomaly: return "BASELINE ANOMALY";
    case DetectionKind::Periodic: return "PERIODIC";
    case DetectionKind::HighActivity: return "HIGH ACTIVITY";
    }
    return "UNKNOWN";
}

const char* severityCode(Severity severity)
{
    switch (severity)
    {
    case Severity::Informational: return "INFORMATIONAL";
    case Severity::Low: return "LOW";
    case Severity::Medium: return "MEDIUM";
    case Severity::High: return "HIGH";
    case Severity::Critical: return "CRITICAL";
    }
    return "INFORMATIONAL";
}

std::string serializeEvidenceJson(const DetectionResult& result)
{
    std::ostringstream output;
    output << std::setprecision(12);
    output << "{\"scoring_version\":" << result.scoringVersion
        << ",\"risk_score\":" << result.riskScore
        << ",\"severity\":\"" << severityCode(result.severity)
        << "\",\"confidence\":" << result.confidence
        << ",\"findings\":[";

    for (size_t findingIndex = 0; findingIndex < result.findings.size(); ++findingIndex)
    {
        if (findingIndex > 0) output << ',';
        const auto& finding = result.findings[findingIndex];
        output << "{\"code\":\"" << detectionKindCode(finding.kind)
            << "\",\"label\":\"" << detectionKindLabel(finding.kind)
            << "\",\"score\":" << finding.scoreContribution
            << ",\"confidence\":" << finding.confidence
            << ",\"evidence\":[";

        for (size_t evidenceIndex = 0; evidenceIndex < finding.evidence.size(); ++evidenceIndex)
        {
            if (evidenceIndex > 0) output << ',';
            const auto& evidence = finding.evidence[evidenceIndex];
            output << "{\"code\":\"" << escapeJson(evidence.code)
                << "\",\"value\":" << finiteValue(evidence.value)
                << ",\"threshold\":" << finiteValue(evidence.threshold)
                << ",\"unit\":\"" << escapeJson(evidence.unit)
                << "\",\"explanation\":\"" << escapeJson(evidence.explanation)
                << "\"}";
        }
        output << "]}";
    }
    output << "]}";
    return output.str();
}
