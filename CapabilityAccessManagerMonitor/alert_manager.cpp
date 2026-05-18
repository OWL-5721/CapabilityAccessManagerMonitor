#include "alert_manager.h"
#include "logger.h"

#include <sqlite3.h>
#include <filesystem>
#include <ctime>
#include <mutex>

static sqlite3* alertDB = nullptr;
static std::mutex  g_alertMutex;

static long long now()
{
    return static_cast<long long>(time(nullptr));
}

void initAlertDB()
{
    std::lock_guard<std::mutex> lock(g_alertMutex);

    const std::string dir =
        "C:\\ProgramData\\CapabilityMonitor";

    std::filesystem::create_directories(dir);

    const std::string dbPath =
        dir + "\\alerts.db";

    Logger::Info("[DB PATH] " + dbPath);

    int rc = sqlite3_open(dbPath.c_str(), &alertDB);

    if (rc != SQLITE_OK)
    {
        Logger::Error("[DB ERROR] Cannot open alerts DB");
        return;
    }

    const char* query =
        "CREATE TABLE IF NOT EXISTS alerts ("
        "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  process       TEXT,"
        "  type          TEXT,"
        "  first_seen    INTEGER,"
        "  last_seen     INTEGER,"
        "  last_notified INTEGER,"
        "  status        TEXT DEFAULT 'OPEN'"
        ");";

    char* errMsg = nullptr;

    rc = sqlite3_exec(alertDB, query, 0, 0, &errMsg);

    if (rc != SQLITE_OK)
    {
        Logger::Error(
            std::string("[DB ERROR] Create table failed: ") + errMsg
        );
        sqlite3_free(errMsg);
    }
    else
    {
        Logger::Info("[DB] alerts.db initialized");
    }
}

void handleAlert(
    const std::string& process,
    const std::string& type
)
{
    std::lock_guard<std::mutex> lock(g_alertMutex);

    if (!alertDB)
    {
        Logger::Error("[DB ERROR] alertDB is null");
        return;
    }

    const char* checkQuery =
        "SELECT id, last_notified "
        "FROM alerts "
        "WHERE process = ? AND status = 'OPEN';";

    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(
        alertDB, checkQuery, -1, &stmt, nullptr
    );

    if (rc != SQLITE_OK)
    {
        Logger::Error(
            std::string("[DB ERROR] prepare check failed: ")
            + sqlite3_errmsg(alertDB)
        );
        return;
    }

    sqlite3_bind_text(
        stmt, 1, process.c_str(), -1, SQLITE_TRANSIENT
    );

    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW)
    {
        int       id = sqlite3_column_int(stmt, 0);
        long long lastNotify = sqlite3_column_int64(stmt, 1);

        sqlite3_finalize(stmt);
        stmt = nullptr;

        const char* updateSeenQuery =
            "UPDATE alerts SET last_seen = ? WHERE id = ?;";

        rc = sqlite3_prepare_v2(
            alertDB, updateSeenQuery, -1, &stmt, nullptr
        );

        if (rc == SQLITE_OK)
        {
            sqlite3_bind_int64(stmt, 1, now());
            sqlite3_bind_int(stmt, 2, id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
            stmt = nullptr;
        }
        else
        {
            Logger::Error(
                std::string("[DB ERROR] update last_seen failed: ")
                + sqlite3_errmsg(alertDB)
            );
            sqlite3_finalize(stmt);
        }

        // Hourly reminder
        if (now() - lastNotify > 3600)
        {
            Logger::Info("[REMINDER] " + process);

            const char* notifyQuery =
                "UPDATE alerts SET last_notified = ? WHERE id = ?;";

            rc = sqlite3_prepare_v2(
                alertDB, notifyQuery, -1, &stmt, nullptr
            );

            if (rc == SQLITE_OK)
            {
                sqlite3_bind_int64(stmt, 1, now());
                sqlite3_bind_int(stmt, 2, id);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            else
            {
                sqlite3_finalize(stmt);
            }
        }

        return;
    }

    sqlite3_finalize(stmt);
    stmt = nullptr;

    Logger::Info("[NEW ALERT] " + process + " | " + type);

    const char* insertQuery =
        "INSERT INTO alerts "
        "  (process, type, first_seen, last_seen, last_notified, status) "
        "VALUES (?, ?, ?, ?, ?, 'OPEN');";

    rc = sqlite3_prepare_v2(
        alertDB, insertQuery, -1, &stmt, nullptr
    );

    if (rc != SQLITE_OK)
    {
        Logger::Error(
            std::string("[DB ERROR] insert prepare failed: ")
            + sqlite3_errmsg(alertDB)
        );
        return;
    }

    long long ts = now();

    sqlite3_bind_text(stmt, 1, process.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, ts);
    sqlite3_bind_int64(stmt, 4, ts);
    sqlite3_bind_int64(stmt, 5, ts);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        Logger::Error(
            std::string("[DB ERROR] insert failed: ")
            + sqlite3_errmsg(alertDB)
        );
    }
    else
    {
        Logger::Info("[DB] Alert inserted successfully");
    }

    sqlite3_finalize(stmt);
}

void markResolved(int alertId)
{
    std::lock_guard<std::mutex> lock(g_alertMutex);

    if (!alertDB)
    {
        Logger::Error("[DB ERROR] alertDB is null in markResolved");
        return;
    }

    const char* query =
        "UPDATE alerts SET status = 'RESOLVED' WHERE id = ?;";

    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(
        alertDB, query, -1, &stmt, nullptr
    );

    if (rc != SQLITE_OK)
    {
        Logger::Error(
            std::string("[DB ERROR] markResolved prepare failed: ")
            + sqlite3_errmsg(alertDB)
        );
        return;
    }

    sqlite3_bind_int(stmt, 1, alertId);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE)
    {
        Logger::Error(
            std::string("[DB ERROR] markResolved step failed: ")
            + sqlite3_errmsg(alertDB)
        );
    }
    else
    {
        Logger::Info(
            "[DB] Alert " + std::to_string(alertId) + " marked RESOLVED"
        );
    }

    sqlite3_finalize(stmt);
}