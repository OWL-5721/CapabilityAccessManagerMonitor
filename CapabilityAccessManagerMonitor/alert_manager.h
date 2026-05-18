#pragma once
#include <string>

void initAlertDB();
void handleAlert(const std::string& process, const std::string& type);
void markResolved(int alertId);