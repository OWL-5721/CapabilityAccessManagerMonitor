#include <windows.h>

#include <chrono>
#include <thread>

#include "alert_manager.h"
#include "snapshot.h"
#include "analyzer.h"
#include "detector.h"
#include "logger.h"

SERVICE_STATUS        g_ServiceStatus{};
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
bool                  g_Running = true;

constexpr int DETECTOR_INTERVAL_SECONDS = 5;

static void UpdateServiceStatus(DWORD state)
{
    g_ServiceStatus.dwCurrentState = state;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode)
    {
    case SERVICE_CONTROL_STOP:
        Logger::Info("Service stop requested");
        g_Running = false;
        UpdateServiceStatus(SERVICE_STOP_PENDING);
        break;

    default:
        break;
    }
}

static void RunMonitoringWindow()
{
    Logger::Info("Starting 5-minute monitoring window");

    auto start = std::chrono::steady_clock::now();

    while (g_Running &&
        (std::chrono::steady_clock::now() - start)
        < std::chrono::minutes(5))
    {
        try
        {
            RunDetector();
        }
        catch (...)
        {
            Logger::Error("Unhandled exception in RunDetector");
        }

        for (int i = 0; i < DETECTOR_INTERVAL_SECONDS; ++i)
        {
            if (!g_Running) return;
            Sleep(1000);
        }
    }

    Logger::Info("Monitoring window completed");
}

static void SleepUntilNextHour()
{
    Logger::Info("Sleeping until next hour");

    auto now = std::chrono::system_clock::now();
    auto nextHour =
        std::chrono::time_point_cast<std::chrono::hours>(now)
        + std::chrono::hours(1);

    while (g_Running &&
        std::chrono::system_clock::now() < nextHour)
    {
        Sleep(1000);
    }
}

void WINAPI ServiceMain(DWORD /*argc*/, LPTSTR* /*argv*/)
{
    g_StatusHandle = RegisterServiceCtrlHandler(
        TEXT("CapabilityMonitor"),
        ServiceCtrlHandler
    );

    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    UpdateServiceStatus(SERVICE_START_PENDING);

    Logger::Info("CapabilityMonitor service starting");

    initAlertDB();

    UpdateServiceStatus(SERVICE_RUNNING);

    Logger::Info("CapabilityMonitor service running");

    while (g_Running)
    {
        RunMonitoringWindow();
        if (!g_Running) break;
        SleepUntilNextHour();
    }

    Logger::Info("CapabilityMonitor service stopping");

    UpdateServiceStatus(SERVICE_STOPPED);
}

int main()
{
    wchar_t svcName[] = L"CapabilityMonitor";

    SERVICE_TABLE_ENTRY ServiceTable[] =
    {
        { svcName, static_cast<LPSERVICE_MAIN_FUNCTION>(ServiceMain) },
        { nullptr, nullptr }
    };

    StartServiceCtrlDispatcher(ServiceTable);

    return 0;
}