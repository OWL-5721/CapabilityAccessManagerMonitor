#pragma once

#include "analyzer.h"
#include "detection_result.h"
#include "detector_pipeline.h"

#include <cstdint>
#include <string>
#include <vector>

DetectionMetrics analyzeProcessTimes(
    std::vector<uint64_t> times,
    uint64_t nowMillis,
    double baselineRate = 0.0
);
DetectionResult buildDetectionResult(
    const std::string& processPath,
    const DetectionMetrics& metrics,
    bool baselineAvailable,
    int baselineSamples
);

void detectLoops(const std::vector<Event>& events);
bool RunDetector();
void resetDetectorSourceState();
