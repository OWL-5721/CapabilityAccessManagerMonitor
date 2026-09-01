#include "analyzer.h"

#include "logger.h"

#include <sqlite3.h>

#include <algorithm>

AnalyzerResult readEvents(
    const std::string& dbPath,
    uint64_t minimumStartFiletime,
    int eventLimit)
{
    AnalyzerResult result;
    sqlite3* db = nullptr;
    const int limit = std::max(1, eventLimit);

    int rc = sqlite3_open_v2(dbPath.c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
    if (rc != SQLITE_OK)
    {
        Logger::Error("[ANALYZER] DB open failed: " + dbPath + " | " +
            (db ? sqlite3_errmsg(db) : sqlite3_errstr(rc)));
        if (db) sqlite3_close(db);
        return result;
    }

    sqlite3_busy_timeout(db, 2000);

    const char* query =
        "SELECT n.LastUsedTimeStart, n.LastUsedTimeStop, n.AppName, n.ServiceName, "
        "a.StringValue, s.StringValue, b.StringValue "
        "FROM NonPackagedUsageHistory n "
        "LEFT JOIN AppNames a ON n.AppName = a.ID "
        "LEFT JOIN ServiceNames s ON n.ServiceName = s.ID "
        "LEFT JOIN BinaryFullPaths b ON n.BinaryFullPath = b.ID "
        "WHERE n.LastUsedTimeStart >= ? "
        "ORDER BY n.LastUsedTimeStart DESC LIMIT ?;";

    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        Logger::Error("[ANALYZER] Query prepare failed: " + std::string(sqlite3_errmsg(db)));
        sqlite3_close(db);
        return result;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(minimumStartFiletime));
    sqlite3_bind_int(stmt, 2, limit + 1);
    result.events.reserve(static_cast<size_t>(limit));

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        if (static_cast<int>(result.events.size()) == limit)
        {
            result.truncated = true;
            break;
        }

        Event event;
        event.start = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
        event.stop = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
        event.appName = sqlite3_column_int(stmt, 2);
        event.serviceName = sqlite3_column_int(stmt, 3);

        const auto text = [stmt](int column, const char* fallback)
        {
            const unsigned char* value = sqlite3_column_text(stmt, column);
            return value ? std::string(reinterpret_cast<const char*>(value)) : std::string(fallback);
        };

        event.appNameStr = text(4, "UNKNOWN");
        event.serviceNameStr = text(5, "UNKNOWN");
        event.binaryPath = text(6, "UNKNOWN");
        result.events.push_back(std::move(event));
    }

    if (rc != SQLITE_DONE && !result.truncated)
    {
        Logger::Error("[ANALYZER] Query step failed: " + std::string(sqlite3_errmsg(db)));
        result.events.clear();
    }
    else
    {
        result.success = true;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (result.truncated)
    {
        Logger::Warning("[ANALYZER] Result reached the " + std::to_string(limit) +
            "-row safety cap; some events may be omitted");
    }

    return result;
}

std::vector<Event> readEvents(const std::string& dbPath)
{
    return readEvents(dbPath, 0, 10000).events;
}
