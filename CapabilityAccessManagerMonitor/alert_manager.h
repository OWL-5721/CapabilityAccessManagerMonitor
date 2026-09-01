#pragma once

#include "detection_result.h"

#include <string>

bool initAlertDB();
void closeAlertDB();
bool handleAlert(const DetectionResult& detection);
bool handleAlert(
    const std::string& processPath,
    const std::string& process,
    const std::string& type
);
void handleAlert(const std::string& process, const std::string& type);
bool markResolved(int alertId);
