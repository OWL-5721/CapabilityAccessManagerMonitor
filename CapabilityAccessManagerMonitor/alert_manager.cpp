#include "alert_manager.h"

#include "logger.h"
#include "risk_scoring.h"
#include "runtime_config.h"

#include <sqlite3.h>

#include <ctime>
#include <filesystem>
#include <mutex>

namespace
{
    sqlite3* g_alertDB = nullptr;
    sqlite3_stmt* g_findOpen = nullptr;
    sqlite3_stmt* g_updateAlert = nullptr;
    sqlite3_stmt* g_updateSeen = nullptr;
    sqlite3_stmt* g_updateNotify = nullptr;
    sqlite3_stmt* g_insertAlert = nullptr;
    sqlite3_stmt* g_deleteFindings = nullptr;
    sqlite3_stmt* g_insertFinding = nullptr;
    sqlite3_stmt* g_insertEvidence = nullptr;
    sqlite3_stmt* g_resolveAlert = nullptr;
    std::mutex g_alertMutex;

    long long currentTime()
    {
        return static_cast<long long>(std::time(nullptr));
    }

    bool execute(const char* sql, const char* context)
    {
        char* errorMessage = nullptr;
        const int rc = sqlite3_exec(g_alertDB, sql, nullptr, nullptr, &errorMessage);
        if (rc == SQLITE_OK) return true;
        Logger::Error(std::string("[DB ERROR] ") + context + ": " +
            (errorMessage ? errorMessage : sqlite3_errmsg(g_alertDB)));
        sqlite3_free(errorMessage);
        return false;
    }

    bool columnExists(const char* table, const char* column)
    {
        const std::string query = "PRAGMA table_info(" + std::string(table) + ");";
        sqlite3_stmt* statement = nullptr;
        if (sqlite3_prepare_v2(g_alertDB, query.c_str(), -1, &statement, nullptr) != SQLITE_OK)
            return false;
        bool found = false;
        while (sqlite3_step(statement) == SQLITE_ROW)
        {
            const unsigned char* name = sqlite3_column_text(statement, 1);
            if (name && std::string(reinterpret_cast<const char*>(name)) == column)
            {
                found = true;
                break;
            }
        }
        sqlite3_finalize(statement);
        return found;
    }

    bool addColumnIfMissing(const char* name, const char* declaration)
    {
        if (columnExists("alerts", name)) return true;
        const std::string sql = "ALTER TABLE alerts ADD COLUMN " + std::string(name) +
            " " + declaration + ";";
        return execute(sql.c_str(), ("add " + std::string(name) + " column").c_str());
    }

    bool migrateSchema()
    {
        if (!execute("BEGIN IMMEDIATE;", "begin migration")) return false;
        bool ok = execute(
            "CREATE TABLE IF NOT EXISTS alerts("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, process TEXT NOT NULL DEFAULT '',"
            "type TEXT NOT NULL DEFAULT '', first_seen INTEGER NOT NULL DEFAULT 0,"
            "last_seen INTEGER NOT NULL DEFAULT 0, last_notified INTEGER NOT NULL DEFAULT 0,"
            "status TEXT NOT NULL DEFAULT 'OPEN');",
            "create alerts table");

        ok = ok && addColumnIfMissing("process_path", "TEXT NOT NULL DEFAULT ''");
        ok = ok && addColumnIfMissing("risk_score", "INTEGER NOT NULL DEFAULT 0");
        ok = ok && addColumnIfMissing("severity", "TEXT NOT NULL DEFAULT 'INFORMATIONAL'");
        ok = ok && addColumnIfMissing("confidence", "INTEGER NOT NULL DEFAULT 0");
        ok = ok && addColumnIfMissing("scoring_version", "INTEGER NOT NULL DEFAULT 0");
        ok = ok && addColumnIfMissing("event_count", "INTEGER NOT NULL DEFAULT 0");
        ok = ok && addColumnIfMissing("peak_rate", "INTEGER NOT NULL DEFAULT 0");
        ok = ok && addColumnIfMissing("average_rate", "REAL NOT NULL DEFAULT 0");
        ok = ok && addColumnIfMissing("baseline_rate", "REAL NOT NULL DEFAULT 0");
        ok = ok && addColumnIfMissing("first_event_time", "INTEGER NOT NULL DEFAULT 0");
        ok = ok && addColumnIfMissing("last_event_time", "INTEGER NOT NULL DEFAULT 0");
        ok = ok && addColumnIfMissing("reason_json", "TEXT NOT NULL DEFAULT '{}'");

        if (ok) ok = execute(
            "UPDATE alerts SET process_path=process WHERE process_path IS NULL OR process_path='';",
            "backfill process paths");
        if (ok) ok = execute(
            "CREATE TABLE IF NOT EXISTS alert_findings("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL,"
            "finding_order INTEGER NOT NULL, kind TEXT NOT NULL, score_contribution INTEGER NOT NULL,"
            "confidence INTEGER NOT NULL, FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE);",
            "create findings table");
        if (ok) ok = execute(
            "CREATE TABLE IF NOT EXISTS alert_evidence("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL,"
            "evidence_order INTEGER NOT NULL, code TEXT NOT NULL, value REAL NOT NULL,"
            "threshold REAL NOT NULL, unit TEXT NOT NULL, explanation TEXT NOT NULL,"
            "FOREIGN KEY(finding_id) REFERENCES alert_findings(id) ON DELETE CASCADE);",
            "create evidence table");
        if (ok) ok = execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_open_identity ON alerts(process_path,type,status);"
            "CREATE INDEX IF NOT EXISTS idx_alerts_status_seen ON alerts(status,last_seen DESC);"
            "CREATE INDEX IF NOT EXISTS idx_alert_findings_alert ON alert_findings(alert_id,finding_order);"
            "CREATE INDEX IF NOT EXISTS idx_alert_evidence_finding ON alert_evidence(finding_id,evidence_order);",
            "create schema indexes");
        if (ok) ok = execute("PRAGMA user_version=3;", "set schema version");

        if (!ok)
        {
            execute("ROLLBACK;", "rollback migration");
            return false;
        }
        return execute("COMMIT;", "commit migration");
    }

    bool prepare(sqlite3_stmt** statement, const char* sql, const char* context)
    {
        const int rc = sqlite3_prepare_v2(g_alertDB, sql, -1, statement, nullptr);
        if (rc == SQLITE_OK) return true;
        Logger::Error(std::string("[DB ERROR] ") + context + ": " + sqlite3_errmsg(g_alertDB));
        return false;
    }

    bool stepDone(sqlite3_stmt* statement, const char* context)
    {
        const int rc = sqlite3_step(statement);
        if (rc == SQLITE_DONE) return true;
        Logger::Error(std::string("[DB ERROR] ") + context + ": " + sqlite3_errmsg(g_alertDB));
        return false;
    }

    void reset(sqlite3_stmt* statement)
    {
        sqlite3_reset(statement);
        sqlite3_clear_bindings(statement);
    }

    void finalizeStatements()
    {
        sqlite3_finalize(g_findOpen); g_findOpen = nullptr;
        sqlite3_finalize(g_updateAlert); g_updateAlert = nullptr;
        sqlite3_finalize(g_updateSeen); g_updateSeen = nullptr;
        sqlite3_finalize(g_updateNotify); g_updateNotify = nullptr;
        sqlite3_finalize(g_insertAlert); g_insertAlert = nullptr;
        sqlite3_finalize(g_deleteFindings); g_deleteFindings = nullptr;
        sqlite3_finalize(g_insertFinding); g_insertFinding = nullptr;
        sqlite3_finalize(g_insertEvidence); g_insertEvidence = nullptr;
        sqlite3_finalize(g_resolveAlert); g_resolveAlert = nullptr;
    }

    bool bindDetectionMetrics(sqlite3_stmt* statement, const DetectionResult& detection, int start)
    {
        const std::string reason = serializeEvidenceJson(detection);
        return sqlite3_bind_int(statement, start, detection.riskScore) == SQLITE_OK &&
            sqlite3_bind_text(statement, start + 1, severityCode(detection.severity), -1, SQLITE_STATIC) == SQLITE_OK &&
            sqlite3_bind_int(statement, start + 2, detection.confidence) == SQLITE_OK &&
            sqlite3_bind_int(statement, start + 3, detection.scoringVersion) == SQLITE_OK &&
            sqlite3_bind_int64(statement, start + 4, static_cast<sqlite3_int64>(detection.eventCount)) == SQLITE_OK &&
            sqlite3_bind_int64(statement, start + 5, static_cast<sqlite3_int64>(detection.peakOneSecondEvents)) == SQLITE_OK &&
            sqlite3_bind_double(statement, start + 6, detection.averageRate) == SQLITE_OK &&
            sqlite3_bind_double(statement, start + 7, detection.baselineRate) == SQLITE_OK &&
            sqlite3_bind_int64(statement, start + 8, static_cast<sqlite3_int64>(detection.firstEventTime)) == SQLITE_OK &&
            sqlite3_bind_int64(statement, start + 9, static_cast<sqlite3_int64>(detection.lastEventTime)) == SQLITE_OK &&
            sqlite3_bind_text(statement, start + 10, reason.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK;
    }

    bool replaceFindings(int alertId, const DetectionResult& detection)
    {
        sqlite3_bind_int(g_deleteFindings, 1, alertId);
        if (!stepDone(g_deleteFindings, "delete previous findings"))
        {
            reset(g_deleteFindings);
            return false;
        }
        reset(g_deleteFindings);

        for (size_t findingIndex = 0; findingIndex < detection.findings.size(); ++findingIndex)
        {
            const auto& finding = detection.findings[findingIndex];
            sqlite3_bind_int(g_insertFinding, 1, alertId);
            sqlite3_bind_int64(g_insertFinding, 2, static_cast<sqlite3_int64>(findingIndex));
            sqlite3_bind_text(g_insertFinding, 3, detectionKindCode(finding.kind), -1, SQLITE_STATIC);
            sqlite3_bind_int(g_insertFinding, 4, finding.scoreContribution);
            sqlite3_bind_int(g_insertFinding, 5, finding.confidence);
            if (!stepDone(g_insertFinding, "insert finding"))
            {
                reset(g_insertFinding);
                return false;
            }
            reset(g_insertFinding);
            const sqlite3_int64 findingId = sqlite3_last_insert_rowid(g_alertDB);

            for (size_t evidenceIndex = 0; evidenceIndex < finding.evidence.size(); ++evidenceIndex)
            {
                const auto& evidence = finding.evidence[evidenceIndex];
                sqlite3_bind_int64(g_insertEvidence, 1, findingId);
                sqlite3_bind_int64(g_insertEvidence, 2, static_cast<sqlite3_int64>(evidenceIndex));
                sqlite3_bind_text(g_insertEvidence, 3, evidence.code.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_double(g_insertEvidence, 4, evidence.value);
                sqlite3_bind_double(g_insertEvidence, 5, evidence.threshold);
                sqlite3_bind_text(g_insertEvidence, 6, evidence.unit.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(g_insertEvidence, 7, evidence.explanation.c_str(), -1, SQLITE_TRANSIENT);
                if (!stepDone(g_insertEvidence, "insert evidence"))
                {
                    reset(g_insertEvidence);
                    return false;
                }
                reset(g_insertEvidence);
            }
        }
        return true;
    }
}

bool initAlertDB()
{
    std::lock_guard<std::mutex> lock(g_alertMutex);
    if (g_alertDB) return true;
    const auto config = getRuntimeConfig();
    std::error_code error;
    std::filesystem::create_directories(config.dataDirectory, error);
    if (error)
    {
        Logger::Error("[DB ERROR] Cannot create data directory: " + error.message());
        return false;
    }

    int rc = sqlite3_open_v2(config.alertDatabasePath.c_str(), &g_alertDB,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK)
    {
        Logger::Error("[DB ERROR] Cannot open alerts DB: " + std::string(
            g_alertDB ? sqlite3_errmsg(g_alertDB) : sqlite3_errstr(rc)));
        if (g_alertDB) sqlite3_close(g_alertDB);
        g_alertDB = nullptr;
        return false;
    }
    sqlite3_busy_timeout(g_alertDB, 3000);
    execute("PRAGMA foreign_keys=ON;", "enable foreign keys");

    if (!migrateSchema() ||
        !prepare(&g_findOpen,
            "SELECT id,last_notified,risk_score FROM alerts WHERE process_path=? AND type=? AND status='OPEN' LIMIT 1;",
            "prepare open lookup") ||
        !prepare(&g_updateAlert,
            "UPDATE alerts SET process=?,last_seen=?,risk_score=?,severity=?,confidence=?,scoring_version=?,"
            "event_count=?,peak_rate=?,average_rate=?,baseline_rate=?,first_event_time=?,last_event_time=?,reason_json=? WHERE id=?;",
            "prepare alert update") ||
        !prepare(&g_updateSeen,
            "UPDATE alerts SET process=?,last_seen=?,event_count=?,peak_rate=?,average_rate=?,baseline_rate=?,"
            "first_event_time=?,last_event_time=? WHERE id=?;",
            "prepare seen update") ||
        !prepare(&g_updateNotify, "UPDATE alerts SET last_notified=? WHERE id=?;", "prepare reminder update") ||
        !prepare(&g_insertAlert,
            "INSERT INTO alerts(process,type,first_seen,last_seen,last_notified,status,process_path,risk_score,severity,"
            "confidence,scoring_version,event_count,peak_rate,average_rate,baseline_rate,first_event_time,last_event_time,reason_json) "
            "VALUES(?,?,?,?,?,'OPEN',?,?,?,?,?,?,?,?,?,?,?,?);",
            "prepare alert insert") ||
        !prepare(&g_deleteFindings, "DELETE FROM alert_findings WHERE alert_id=?;", "prepare findings delete") ||
        !prepare(&g_insertFinding,
            "INSERT INTO alert_findings(alert_id,finding_order,kind,score_contribution,confidence) VALUES(?,?,?,?,?);",
            "prepare finding insert") ||
        !prepare(&g_insertEvidence,
            "INSERT INTO alert_evidence(finding_id,evidence_order,code,value,threshold,unit,explanation) VALUES(?,?,?,?,?,?,?);",
            "prepare evidence insert") ||
        !prepare(&g_resolveAlert, "UPDATE alerts SET status='RESOLVED' WHERE id=?;", "prepare resolve update"))
    {
        finalizeStatements();
        sqlite3_close(g_alertDB);
        g_alertDB = nullptr;
        return false;
    }
    Logger::Info("[DB] alerts.db schema v3 initialized at " + config.alertDatabasePath);
    return true;
}

void closeAlertDB()
{
    std::lock_guard<std::mutex> lock(g_alertMutex);
    finalizeStatements();
    if (g_alertDB)
    {
        sqlite3_close(g_alertDB);
        g_alertDB = nullptr;
    }
}

bool handleAlert(const DetectionResult& detection)
{
    std::lock_guard<std::mutex> lock(g_alertMutex);
    if (!g_alertDB || detection.findings.empty()) return false;
    const long long timestamp = currentTime();

    if (!execute("BEGIN IMMEDIATE;", "begin alert write")) return false;
    sqlite3_bind_text(g_findOpen, 1, detection.processPath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_findOpen, 2, detection.legacyType.c_str(), -1, SQLITE_TRANSIENT);
    const int findRc = sqlite3_step(g_findOpen);

    int alertId = 0;
    long long lastNotified = timestamp;
    bool ok = true;
    if (findRc == SQLITE_ROW)
    {
        alertId = sqlite3_column_int(g_findOpen, 0);
        lastNotified = sqlite3_column_int64(g_findOpen, 1);
        const int previousRisk = sqlite3_column_int(g_findOpen, 2);
        reset(g_findOpen);

        const bool stronger = detection.riskScore >= previousRisk;
        if (stronger)
        {
            sqlite3_bind_text(g_updateAlert, 1, detection.process.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(g_updateAlert, 2, timestamp);
            ok = bindDetectionMetrics(g_updateAlert, detection, 3);
            sqlite3_bind_int(g_updateAlert, 14, alertId);
            ok = ok && stepDone(g_updateAlert, "update alert evidence");
            reset(g_updateAlert);
            if (ok) ok = replaceFindings(alertId, detection);
        }
        else
        {
            sqlite3_bind_text(g_updateSeen, 1, detection.process.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(g_updateSeen, 2, timestamp);
            sqlite3_bind_int64(g_updateSeen, 3, static_cast<sqlite3_int64>(detection.eventCount));
            sqlite3_bind_int64(g_updateSeen, 4, static_cast<sqlite3_int64>(detection.peakOneSecondEvents));
            sqlite3_bind_double(g_updateSeen, 5, detection.averageRate);
            sqlite3_bind_double(g_updateSeen, 6, detection.baselineRate);
            sqlite3_bind_int64(g_updateSeen, 7, static_cast<sqlite3_int64>(detection.firstEventTime));
            sqlite3_bind_int64(g_updateSeen, 8, static_cast<sqlite3_int64>(detection.lastEventTime));
            sqlite3_bind_int(g_updateSeen, 9, alertId);
            ok = stepDone(g_updateSeen, "update weaker alert observation");
            reset(g_updateSeen);
        }
    }
    else
    {
        reset(g_findOpen);
        if (findRc != SQLITE_DONE) ok = false;
        if (ok)
        {
            sqlite3_bind_text(g_insertAlert, 1, detection.process.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(g_insertAlert, 2, detection.legacyType.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(g_insertAlert, 3, timestamp);
            sqlite3_bind_int64(g_insertAlert, 4, timestamp);
            sqlite3_bind_int64(g_insertAlert, 5, timestamp);
            sqlite3_bind_text(g_insertAlert, 6, detection.processPath.c_str(), -1, SQLITE_TRANSIENT);
            ok = bindDetectionMetrics(g_insertAlert, detection, 7) && stepDone(g_insertAlert, "insert alert");
            reset(g_insertAlert);
            alertId = static_cast<int>(sqlite3_last_insert_rowid(g_alertDB));
        }
    }

    if (ok && findRc == SQLITE_DONE) ok = replaceFindings(alertId, detection);
    if (ok && timestamp - lastNotified >= 3600)
    {
        sqlite3_bind_int64(g_updateNotify, 1, timestamp);
        sqlite3_bind_int(g_updateNotify, 2, alertId);
        ok = stepDone(g_updateNotify, "update reminder timestamp");
        reset(g_updateNotify);
    }

    if (ok) ok = execute("COMMIT;", "commit alert write");
    else execute("ROLLBACK;", "rollback alert write");
    if (ok) Logger::Info("[ALERT] " + detection.process + " | score=" +
        std::to_string(detection.riskScore) + " | " + detection.legacyType);
    return ok;
}

bool handleAlert(const std::string& processPath, const std::string& process, const std::string& type)
{
    DetectionResult detection;
    detection.processPath = processPath;
    detection.process = process;
    detection.legacyType = type;
    detection.findings.push_back({ DetectionKind::HighActivity, 0, 0, {} });
    return handleAlert(detection);
}

void handleAlert(const std::string& process, const std::string& type)
{
    handleAlert(process, process, type);
}

bool markResolved(int alertId)
{
    std::lock_guard<std::mutex> lock(g_alertMutex);
    if (!g_alertDB) return false;
    sqlite3_bind_int(g_resolveAlert, 1, alertId);
    const bool resolved = stepDone(g_resolveAlert, "resolve alert");
    reset(g_resolveAlert);
    return resolved;
}
