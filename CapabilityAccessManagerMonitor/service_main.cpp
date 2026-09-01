#include <windows.h>

#include "alert_manager.h"
#include "baseline.h"
#include "detector.h"
#include "logger.h"

#include <algorithm>
#include <chrono>
#include <exception>
#include <string>

namespace
{
    SERVICE_STATUS g_serviceStatus{};
    SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
    HANDLE g_stopEvent = nullptr;
    constexpr DWORD DETECTOR_INTERVAL_MS = 5000;
    constexpr DWORD MONITORING_WINDOW_MS = 5 * 60 * 1000;

    std::string windowsErrorMessage(DWORD error)
    {
        return "Windows error " + std::to_string(error);
    }

    bool updateServiceStatus(DWORD state, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0)
    {
        g_serviceStatus.dwCurrentState = state;
        g_serviceStatus.dwWin32ExitCode = win32ExitCode;
        g_serviceStatus.dwWaitHint = waitHint;
        g_serviceStatus.dwControlsAccepted = state == SERVICE_RUNNING
            ? SERVICE_ACCEPT_STOP
            : 0;
        return g_statusHandle && SetServiceStatus(g_statusHandle, &g_serviceStatus) != FALSE;
    }

    bool stopRequested()
    {
        return g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0;
    }

    bool waitOrStop(DWORD milliseconds)
    {
        return g_stopEvent && WaitForSingleObject(g_stopEvent, milliseconds) == WAIT_OBJECT_0;
    }

    void runMonitoringWindow()
    {
        Logger::Info("Starting 5-minute monitoring window");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(5);

        while (!stopRequested() && std::chrono::steady_clock::now() < deadline)
        {
            try
            {
                RunDetector();
            }
            catch (const std::exception& error)
            {
                Logger::Error(std::string("Unhandled detector exception: ") + error.what());
            }
            catch (...)
            {
                Logger::Error("Unhandled non-standard detector exception");
            }

            if (waitOrStop(DETECTOR_INTERVAL_MS)) break;
        }

        if (isBaselineDirty() && !saveBaseline())
        {
            Logger::Error("Failed to persist baseline after monitoring window");
        }
        Logger::Info("Monitoring window completed");
    }

    void sleepUntilNextHour()
    {
        const auto now = std::chrono::system_clock::now();
        const auto nextHour = std::chrono::time_point_cast<std::chrono::hours>(now) +
            std::chrono::hours(1);
        const auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(nextHour - now);
        const auto bounded = static_cast<DWORD>(std::min<long long>(delay.count(), MAXDWORD));
        waitOrStop(bounded);
    }
}

void WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    if (ctrlCode == SERVICE_CONTROL_STOP && g_stopEvent)
    {
        updateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        SetEvent(g_stopEvent);
    }
}

void WINAPI ServiceMain(DWORD, LPTSTR*)
{
    g_statusHandle = RegisterServiceCtrlHandler(TEXT("CapabilityMonitor"), ServiceCtrlHandler);
    if (!g_statusHandle)
    {
        Logger::Error("RegisterServiceCtrlHandler failed: " + windowsErrorMessage(GetLastError()));
        return;
    }

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwServiceSpecificExitCode = 0;
    updateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 10000);

    g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent)
    {
        const DWORD error = GetLastError();
        Logger::Error("CreateEvent failed: " + windowsErrorMessage(error));
        updateServiceStatus(SERVICE_STOPPED, error);
        return;
    }

    if (!loadBaseline() || !initAlertDB())
    {
        Logger::Error("CapabilityMonitor initialization failed");
        closeAlertDB();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        updateServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    resetDetectorSourceState();
    updateServiceStatus(SERVICE_RUNNING);
    Logger::Info("CapabilityMonitor service running");

    while (!stopRequested())
    {
        runMonitoringWindow();
        if (!stopRequested()) sleepUntilNextHour();
    }

    saveBaseline();
    closeAlertDB();
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    updateServiceStatus(SERVICE_STOPPED);
}

int main()
{
    TCHAR serviceName[] = TEXT("CapabilityMonitor");
    SERVICE_TABLE_ENTRY serviceTable[] =
    {
        { serviceName, static_cast<LPSERVICE_MAIN_FUNCTION>(ServiceMain) },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcher(serviceTable))
    {
        const DWORD error = GetLastError();
        Logger::Error("StartServiceCtrlDispatcher failed: " + windowsErrorMessage(error));
        return static_cast<int>(error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT ? 2 : 1);
    }
    return 0;
}
