#include "snapshot.h"
#include "logger.h"
#include <sqlite3.h>
#include <iostream>

bool backupDatabase(
    const std::string& srcPath,
    const std::string& dstPath
)
{
    sqlite3* src = nullptr;
    sqlite3* dst = nullptr;

    if (sqlite3_open_v2(
        srcPath.c_str(), &src, SQLITE_OPEN_READONLY, nullptr
    ) != SQLITE_OK)
    {
        Logger::Error(
            "[SNAPSHOT] Failed to open source DB: " + srcPath
        );
        return false;
    }

    if (sqlite3_open(dstPath.c_str(), &dst) != SQLITE_OK)
    {
        Logger::Error(
            "[SNAPSHOT] Failed to open destination DB: " + dstPath
        );
        sqlite3_close(src);
        return false;
    }

    sqlite3_backup* backup =
        sqlite3_backup_init(dst, "main", src, "main");

    if (!backup)
    {
        Logger::Error("[SNAPSHOT] Backup init failed");
        sqlite3_close(src);
        sqlite3_close(dst);
        return false;
    }

    int rc = sqlite3_backup_step(backup, -1);

    sqlite3_backup_finish(backup);  

    sqlite3_close(src);
    sqlite3_close(dst);

    if (rc != SQLITE_DONE)
    {
        Logger::Error(
            "[SNAPSHOT] Backup step failed with code: "
            + std::to_string(rc)
        );
        return false;
    }

    Logger::Info("[SNAPSHOT] Backup completed successfully");
    return true;
}