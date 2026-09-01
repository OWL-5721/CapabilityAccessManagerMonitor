#include "snapshot.h"

#include "logger.h"

#include <sqlite3.h>

#include <chrono>
#include <filesystem>
#include <thread>

bool backupDatabase(const std::string& srcPath, const std::string& dstPath)
{
    sqlite3* src = nullptr;
    sqlite3* dst = nullptr;

    int rc = sqlite3_open_v2(srcPath.c_str(), &src, SQLITE_OPEN_READONLY, nullptr);
    if (rc != SQLITE_OK)
    {
        Logger::Error("[SNAPSHOT] Failed to open source DB: " + srcPath + " | " +
            (src ? sqlite3_errmsg(src) : sqlite3_errstr(rc)));
        if (src) sqlite3_close(src);
        return false;
    }
    sqlite3_busy_timeout(src, 2000);

    std::error_code error;
    const std::filesystem::path destination(dstPath);
    if (!destination.parent_path().empty())
    {
        std::filesystem::create_directories(destination.parent_path(), error);
    }
    if (error)
    {
        Logger::Error("[SNAPSHOT] Failed to create destination directory: " + error.message());
        sqlite3_close(src);
        return false;
    }

    rc = sqlite3_open_v2(dstPath.c_str(), &dst, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK)
    {
        Logger::Error("[SNAPSHOT] Failed to open destination DB: " + dstPath + " | " +
            (dst ? sqlite3_errmsg(dst) : sqlite3_errstr(rc)));
        sqlite3_close(src);
        if (dst) sqlite3_close(dst);
        return false;
    }
    sqlite3_busy_timeout(dst, 2000);

    sqlite3_backup* backup = sqlite3_backup_init(dst, "main", src, "main");
    if (!backup)
    {
        Logger::Error("[SNAPSHOT] Backup init failed: " + std::string(sqlite3_errmsg(dst)));
        sqlite3_close(src);
        sqlite3_close(dst);
        return false;
    }

    constexpr int MAX_RETRIES = 5;
    int retries = 0;
    do
    {
        rc = sqlite3_backup_step(backup, -1);
        if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED)
        {
            ++retries;
            std::this_thread::sleep_for(std::chrono::milliseconds(50 * retries));
        }
    } while ((rc == SQLITE_BUSY || rc == SQLITE_LOCKED) && retries < MAX_RETRIES);

    const int finishRc = sqlite3_backup_finish(backup);
    if (rc == SQLITE_DONE && finishRc != SQLITE_OK)
    {
        rc = finishRc;
    }

    if (rc != SQLITE_DONE && rc != SQLITE_OK)
    {
        Logger::Error("[SNAPSHOT] Backup failed with code " + std::to_string(rc) +
            ": " + sqlite3_errstr(rc));
    }

    sqlite3_close(src);
    sqlite3_close(dst);
    return rc == SQLITE_DONE || rc == SQLITE_OK;
}
