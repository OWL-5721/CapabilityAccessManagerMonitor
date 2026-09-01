#include "alert_manager.h"
#include "baseline.h"
#include "detector.h"
#include "detector_pipeline.h"
#include "risk_scoring.h"
#include "runtime_config.h"
#include "utils.h"

#include <sqlite3.h>

#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    void require(bool condition, const std::string& message)
    {
        if (!condition) throw std::runtime_error(message);
    }

    void requireNear(double actual, double expected, double tolerance, const std::string& message)
    {
        require(std::fabs(actual - expected) <= tolerance, message);
    }

    RuntimeConfig makeTestConfig(const std::filesystem::path& root)
    {
        const std::string data = root.string();
        return {
            (root / "source.db").string(),
            data,
            (root / "snapshot.db").string(),
            (root / "alerts.db").string(),
            (root / "baseline.txt").string(),
            (root / "log.txt").string(),
            false,
            10000
        };
    }

    int scalar(sqlite3* db, const char* query)
    {
        sqlite3_stmt* statement = nullptr;
        require(sqlite3_prepare_v2(db, query, -1, &statement, nullptr) == SQLITE_OK,
            "failed to prepare scalar query");
        require(sqlite3_step(statement) == SQLITE_ROW, "failed to step scalar query");
        const int result = sqlite3_column_int(statement, 0);
        sqlite3_finalize(statement);
        return result;
    }

    void testFiletime()
    {
        uint64_t millis = 123;
        require(!tryFiletimeToMillis(FILETIME_UNIX_EPOCH_OFFSET - 1, millis),
            "pre-epoch FILETIME must be rejected");
        require(millis == 0, "rejected FILETIME must clear output");
        require(tryFiletimeToMillis(FILETIME_UNIX_EPOCH_OFFSET + 42'000ULL, millis),
            "valid FILETIME must convert");
        require(millis == 4, "FILETIME conversion mismatch");
        require(filetimeToMillis(unixMillisToFiletime(123456)) == 123456,
            "FILETIME round trip mismatch");
    }

    void testDetectorBoundaries()
    {
        constexpr uint64_t now = 1'000'000ULL;
        std::vector<uint64_t> tight;
        for (size_t index = 0; index < 20; ++index) tight.push_back(now - 1000 + index * 49);
        const auto tightMetrics = analyzeProcessTimes(tight, now);
        require(tightMetrics.tightRunEvents == 20, "tight run must count events");
        require(tightMetrics.type.find("TIGHT LOOP") != std::string::npos,
            "tight loop should trigger");

        std::vector<uint64_t> exactGap;
        for (size_t index = 0; index < 20; ++index) exactGap.push_back(now - 1000 + index * 50);
        const auto exactMetrics = analyzeProcessTimes(exactGap, now);
        require(exactMetrics.type.find("TIGHT LOOP") == std::string::npos,
            "exactly 50 ms must not be tight");

        std::vector<uint64_t> steady;
        for (size_t index = 0; index < 20; ++index) steady.push_back(now - 1900 + index * 100);
        const auto steadyMetrics = analyzeProcessTimes(steady, now);
        requireNear(steadyMetrics.averageRate, 10.0, 0.0001,
            "average rate must use intervals");
        require(steadyMetrics.periodic, "regular timing should be periodic");

        const auto anomaly = analyzeProcessTimes(steady, now, 4.0);
        require(anomaly.baselineAnomaly, "rate above 2x baseline must be anomalous");
    }

    void testModularDetectorPipeline()
    {
        ProcessDetectionContext context;
        context.metrics.eventCount = 51;
        context.metrics.tightRunEvents = 15;
        context.metrics.peakOneSecondEvents = 51;
        context.metrics.averageRate = 20.0;
        context.metrics.baselineRate = 5.0;
        context.metrics.baselineAnomaly = true;
        context.metrics.periodic = true;
        context.baselineAvailable = true;
        context.baselineSamples = 100;

        TightLoopDetector tight;
        BurstLoopDetector burst;
        SteadyLoopDetector steady;
        BaselineAnomalyDetector baseline;
        PeriodicDetector periodic;
        HighActivityDetector highActivity;
        require(tight.Analyze(context).has_value(), "tight detector positive boundary mismatch");
        require(burst.Analyze(context).has_value(), "burst detector positive boundary mismatch");
        require(steady.Analyze(context).has_value(), "steady detector positive boundary mismatch");
        require(baseline.Analyze(context).has_value(), "baseline detector positive boundary mismatch");
        require(periodic.Analyze(context).has_value(), "periodic detector positive mismatch");
        require(highActivity.Analyze(context).has_value(), "high-activity detector positive boundary mismatch");

        ProcessDetectionContext boundary = context;
        boundary.metrics.eventCount = 50;
        boundary.metrics.tightRunEvents = 14;
        boundary.metrics.peakOneSecondEvents = 50;
        boundary.metrics.averageRate = 15.0;
        boundary.metrics.baselineRate = 7.5;
        boundary.metrics.baselineAnomaly = false;
        boundary.metrics.periodic = false;
        require(!tight.Analyze(boundary).has_value(), "tight detector must reject 14 events");
        require(!burst.Analyze(boundary).has_value(), "burst detector must reject exactly 50 events");
        require(!steady.Analyze(boundary).has_value(), "steady detector must reject exactly 15/sec");
        require(!baseline.Analyze(boundary).has_value(), "baseline detector must reject exactly 2x");
        require(!periodic.Analyze(boundary).has_value(), "periodic detector must reject false metric");
        require(!highActivity.Analyze(boundary).has_value(), "high activity must reject exactly 50 events");

        DetectionEngine engine;
        const auto findings = engine.Analyze(context);
        require(findings.size() == 6, "all detector modules should fire");
        require(findings[0].kind == DetectionKind::TightLoop &&
            findings[1].kind == DetectionKind::BurstLoop &&
            findings[2].kind == DetectionKind::SteadyLoop &&
            findings[3].kind == DetectionKind::BaselineAnomaly &&
            findings[4].kind == DetectionKind::Periodic &&
            findings[5].kind == DetectionKind::HighActivity,
            "default detector order is a compatibility contract");
        require(buildLegacyType(findings) ==
            "TIGHT LOOP BURST LOOP STEADY LOOP BASELINE ANOMALY PERIODIC HIGH ACTIVITY",
            "legacy type projection mismatch");
        require(hasFinding(findings, DetectionKind::BaselineAnomaly),
            "baseline anomaly finding must control learning exclusion");

        const auto result = scoreFindings(context, findings);
        require(result.riskScore == 100, "modular finding score must be capped at 100");
        require(result.severity == Severity::Critical, "modular severity mismatch");
        require(result.confidence == 80, "modular confidence mismatch");
        require(result.legacyType == buildLegacyType(findings),
            "scoring must preserve engine finding order");

        DetectionMetrics metrics = context.metrics;
        metrics.firstEventTime = 100;
        metrics.lastEventTime = 200;
        const auto built = buildDetectionResult(
            "C:\\Program Files\\Example App\\agent.exe", metrics, true, 100);
        require(built.process == "agent.exe", "process display name extraction mismatch");
        require(built.firstEventTime == 100 && built.lastEventTime == 200,
            "event range was not copied to detection result");
        require(built.legacyType == result.legacyType && built.riskScore == result.riskScore &&
            built.confidence == result.confidence,
            "buildDetectionResult must preserve engine/scoring parity");
    }

    void testRiskScoring()
    {
        RiskScoringInput input;
        input.tightLoop = true;
        input.burstLoop = true;
        input.baselineAnomaly = true;
        input.periodic = true;
        input.eventCount = 80;
        input.peakOneSecondEvents = 60;
        input.tightRunEvents = 20;
        input.averageRate = 30.0;
        input.baselineRate = 10.0;
        input.baselineAvailable = true;
        input.baselineSamples = 100;

        const auto result = scoreDetection(input);
        require(result.riskScore == 95, "risk score contribution mismatch");
        require(result.severity == Severity::Critical, "critical severity boundary mismatch");
        require(result.confidence == 89, "confidence calculation mismatch");
        require(result.findings.size() == 4, "expected four ordered findings");
        require(result.findings[0].kind == DetectionKind::TightLoop &&
            result.findings[1].kind == DetectionKind::BurstLoop &&
            result.findings[2].kind == DetectionKind::BaselineAnomaly &&
            result.findings[3].kind == DetectionKind::Periodic,
            "finding order must be deterministic");
        require(severityForRiskScore(19) == Severity::Informational &&
            severityForRiskScore(20) == Severity::Low &&
            severityForRiskScore(40) == Severity::Medium &&
            severityForRiskScore(60) == Severity::High &&
            severityForRiskScore(80) == Severity::Critical,
            "severity bands mismatch");

        input.averageRate = std::numeric_limits<double>::quiet_NaN();
        input.baselineRate = std::numeric_limits<double>::infinity();
        const auto sanitized = scoreDetection(input);
        require(sanitized.averageRate == 0.0 && sanitized.baselineRate == 0.0,
            "non-finite metrics must be sanitized");
        const std::string json = serializeEvidenceJson(result);
        require(json.find("\"code\":\"tight_loop\"") != std::string::npos,
            "evidence JSON missing stable finding code");
    }

    void testBaselineMigration(const std::filesystem::path& root)
    {
        clearBaselineForTesting();
        {
            std::ofstream legacy(root / "baseline.txt");
            legacy << "C:\\Program Files\\Example App\\agent.exe 1.25 7\n";
        }

        require(loadBaseline(), "legacy baseline load failed");
        const std::string path = "C:\\Program Files\\Example App\\agent.exe";
        require(baselineDB.count(path) == 1, "legacy path with spaces was not preserved");
        require(isBaselineDirty(), "legacy baseline must schedule migration");
        require(saveBaseline(), "v2 baseline save failed");

        clearBaselineForTesting();
        require(loadBaseline(), "v2 baseline reload failed");
        require(baselineDB.count(path) == 1, "v2 path did not round trip");
    }

    void testAlertMigrationAndIdentity(const std::filesystem::path& root)
    {
        sqlite3* db = nullptr;
        require(sqlite3_open((root / "alerts.db").string().c_str(), &db) == SQLITE_OK,
            "failed to create legacy alert DB");
        require(sqlite3_exec(db,
            "CREATE TABLE alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, process TEXT, type TEXT, "
            "first_seen INTEGER, last_seen INTEGER, last_notified INTEGER, status TEXT DEFAULT 'OPEN');"
            "INSERT INTO alerts(process,type,first_seen,last_seen,last_notified,status) "
            "VALUES('legacy.exe','TIGHT LOOP',1,1,1,'OPEN');",
            nullptr, nullptr, nullptr) == SQLITE_OK,
            "failed to seed legacy alert DB");
        sqlite3_close(db);

        require(initAlertDB(), "alert DB migration failed");
        DetectionResult structured;
        structured.processPath = "C:\\A\\same.exe";
        structured.process = "same.exe";
        structured.legacyType = "TIGHT LOOP";
        structured.riskScore = 30;
        structured.severity = Severity::Low;
        structured.confidence = 70;
        structured.scoringVersion = 1;
        structured.eventCount = 20;
        structured.peakOneSecondEvents = 20;
        structured.averageRate = 15.5;
        structured.baselineRate = 5.0;
        structured.firstEventTime = 100;
        structured.lastEventTime = 200;
        structured.findings.push_back({ DetectionKind::TightLoop, 30, 70,
            {{ "tight_run_events", 20.0, 15.0, "events", "test evidence" }} });
        require(handleAlert(structured), "failed to insert structured alert");
        require(handleAlert("C:\\B\\same.exe", "same.exe", "TIGHT LOOP"),
            "failed to insert second full-path alert");
        require(handleAlert("C:\\A\\same.exe", "same.exe", "BURST LOOP"),
            "failed to insert distinct alert type");
        structured.riskScore = 60;
        structured.severity = Severity::High;
        structured.confidence = 90;
        structured.eventCount = 40;
        require(handleAlert(structured), "failed to update structured alert");
        closeAlertDB();

        require(sqlite3_open((root / "alerts.db").string().c_str(), &db) == SQLITE_OK,
            "failed to reopen alert DB");
        require(scalar(db, "SELECT COUNT(*) FROM alerts WHERE status='OPEN';") == 4,
            "alert identity must separate legacy, paths, and types");
        require(scalar(db, "PRAGMA user_version;") == 3, "schema version was not migrated");
        require(scalar(db, "SELECT risk_score FROM alerts WHERE process_path='C:\\A\\same.exe' AND type='TIGHT LOOP';") == 60,
            "stronger repeat alert did not refresh score");
        require(scalar(db, "SELECT COUNT(*) FROM alert_findings;") >= 1,
            "normalized finding evidence was not persisted");
        require(scalar(db, "SELECT COUNT(*) FROM alert_evidence;") >= 1,
            "normalized evidence details were not persisted");
        require(scalar(db, "SELECT COUNT(process) FROM alerts;") == 4,
            "legacy notifier columns must remain readable");
        sqlite3_close(db);

        require(initAlertDB(), "schema v3 migration must be idempotent");
        closeAlertDB();
    }
}

int main()
{
    const auto root = std::filesystem::temp_directory_path() /
        "capability-monitor-tests";
    std::error_code error;
    std::filesystem::remove_all(root, error);
    std::filesystem::create_directories(root);
    setRuntimeConfigForTesting(makeTestConfig(root));

    try
    {
        testFiletime();
        testDetectorBoundaries();
        testModularDetectorPipeline();
        testRiskScoring();
        testBaselineMigration(root);
        testAlertMigrationAndIdentity(root);
        closeAlertDB();
        resetRuntimeConfig();
        std::filesystem::remove_all(root, error);
        std::cout << "All CapabilityMonitor tests passed\n";
        return 0;
    }
    catch (const std::exception& exception)
    {
        closeAlertDB();
        resetRuntimeConfig();
        std::cerr << "Test failure: " << exception.what() << '\n';
        return 1;
    }
}
