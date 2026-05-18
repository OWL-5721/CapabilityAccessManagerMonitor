//#include "snapshot.h"
//#include "analyzer.h"
//#include "detector.h"
//#include <iostream>
//
//#include "alert_manager.h"
//
//int main() {
//
//    initAlertDB();
//
//
//    std::string source = "C:\\ProgramData\\Microsoft\\Windows\\CapabilityAccessManager\\CapabilityAccessManager.db";
//    std::string dest = "D:\\SafeSnapshots\\copy.db";
//
//    std::cout << "[*] Backing up DB...\n";
//
//    if (!backupDatabase(source, dest)) {
//        std::cerr << "Backup failed\n";
//        return 1;
//    }
//
//    std::cout << "[*] Reading events...\n";
//    auto events = readEvents(dest);
//
//    std::cout << "[*] Detecting loops...\n";
//    detectLoops(events);
//
//    return 0;
//}