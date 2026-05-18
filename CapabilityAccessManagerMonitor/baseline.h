#pragma once
#include <string>
#include <unordered_map>

struct Baseline {
    double avgRate = 0.0;
    int samples = 0;
};

extern std::unordered_map<std::string, Baseline> baselineDB;

void loadBaseline();
void saveBaseline();
void updateBaseline(const std::string& process, double avgRate);