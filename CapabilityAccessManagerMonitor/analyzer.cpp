#include "analyzer.h"
#include "logger.h"
#include <sqlite3.h>
#include <iostream>

static constexpr int EVENT_LIMIT = 10000;

std::vector<Event> readEvents(const std::string& dbPath)
{
    sqlite3* db = nullptr;
    std::vector<Event> events;

    if (sqlite3_open_v2(
        dbPath.c_str(), &db, SQLITE_OPEN_READONLY, nullptr
    ) != SQLITE_OK)
    {
        Logger::Error("[ANALYZER] DB open failed: " + dbPath);
        return events;
    }

    const char* query =
        "SELECT "
        "  n.LastUsedTimeStart, "
        "  n.LastUsedTimeStop, "
        "  n.AppName, "
        "  n.ServiceName, "
        "  a.StringValue, "
        "  s.StringValue, "
        "  b.StringValue "
        "FROM NonPackagedUsageHistory n "
        "LEFT JOIN AppNames       a ON n.AppName       = a.ID "
        "LEFT JOIN ServiceNames   s ON n.ServiceName   = s.ID "
        "LEFT JOIN BinaryFullPaths b ON n.BinaryFullPath = b.ID "
        "ORDER BY n.LastUsedTimeStart DESC "
        "LIMIT 10000;";

    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK)
    {
        Logger::Error("[ANALYZER] Query prepare failed");
        sqlite3_close(db);
        return events;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        Event e;

        e.start = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
        e.stop = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));

        e.appName = sqlite3_column_int(stmt, 2);
        e.serviceName = sqlite3_column_int(stmt, 3);

        const unsigned char* appTxt =
            sqlite3_column_text(stmt, 4);
        e.appNameStr =
            appTxt ? reinterpret_cast<const char*>(appTxt) : "UNKNOWN";

        const unsigned char* svcTxt =
            sqlite3_column_text(stmt, 5);
        e.serviceNameStr =
            svcTxt ? reinterpret_cast<const char*>(svcTxt) : "UNKNOWN";

        const unsigned char* binTxt =
            sqlite3_column_text(stmt, 6);
        e.binaryPath =
            binTxt ? reinterpret_cast<const char*>(binTxt) : "UNKNOWN";

        events.push_back(e);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (static_cast<int>(events.size()) == EVENT_LIMIT)
    {
        Logger::Warning(
            "[ANALYZER] Result set hit the 10 000-row cap — "
            "some events may have been truncated."
        );
    }

    return events;
}