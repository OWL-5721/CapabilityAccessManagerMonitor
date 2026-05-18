# CapabilityMonitor

A Windows background service that monitors process launch activity via the Windows `CapabilityAccessManager.db`, detects abnormal patterns (tight loops, burst launches, steady high-rate activity, and baseline anomalies), and writes structured alerts to a shared SQLite database consumed by the companion **CapabilityMonitor Notifier**.

---

## How It Works

Windows maintains a database at:

```
C:\ProgramData\Microsoft\Windows\CapabilityAccessManager\CapabilityAccessManager.db
```

This database records every time a process requests a capability (camera, microphone, location, etc.). CapabilityMonitor takes periodic read-only snapshots of that database, analyzes the event timings per process, and raises alerts when a process exhibits suspicious looping or abnormally high launch rates.

**Cycle:**
1. Every hour, a 5-minute active monitoring window opens.
2. Inside the window, the detector runs every 5 seconds.
3. Each run snapshots the live DB → analyzes events → updates baselines → writes alerts.
4. The service then sleeps until the next hour boundary.

---

## Architecture

```
service_main.cpp
    └── RunMonitoringWindow()          every hour, 5-min window
            └── RunDetector()          every 5 seconds
                    ├── backupDatabase()       snapshot.cpp  — SQLite online backup
                    ├── readEvents()           analyzer.h    — parse events from snapshot
                    └── detectLoops()          detector.cpp  — classify & alert
                            ├── loadBaseline() / saveBaseline()   baseline.h
                            └── handleAlert()                     alert_manager.cpp
```

### Components

| File | Responsibility |
|---|---|
| `service_main.cpp` | Windows Service entry point, control handler, hourly scheduling |
| `detector.cpp` | Core detection logic — classifies process activity into loop types |
| `analyzer.h` | `Event` struct + `readEvents()` — reads raw events from DB snapshot |
| `baseline.h/cpp` | Persists per-process average rates across runs for anomaly detection |
| `alert_manager.cpp` | SQLite-backed alert store with deduplication and hourly reminders |
| `snapshot.cpp` | Safe read-only backup of the live CapabilityAccessManager DB |
| `logger.cpp` | Thread-safe append logger → `C:\ProgramData\CapabilityMonitor\log.txt` |
| `utils.cpp` | FILETIME → milliseconds conversion |

---

## Detection Logic

All detection operates within an 8-hour sliding window per process. A minimum of 10–20 events is required before any classification is attempted.

| Alert Type | Condition |
|---|---|
| `TIGHT LOOP` | 15+ consecutive launches with < 50 ms between them |
| `BURST LOOP` | Peak rate > 50 events/sec within any 1-second window |
| `STEADY LOOP` | Long-run average rate > 15 events/sec |
| `BASELINE ANOMALY` | Current average rate > 2× the process's historical baseline |
| `PERIODIC` | Inter-event gap coefficient of variation < 10% (highly regular timing) |
| `HIGH ACTIVITY` | More than 50 events recorded in the window |

Multiple types can be raised simultaneously for a single process (e.g. `BURST LOOP BASELINE ANOMALY`).

---

## Alert Deduplication

`alert_manager.cpp` prevents alert spam:

- If an alert for a process is already `OPEN`, only `last_seen` is updated.
- A reminder log entry is written at most once per hour (`last_notified` gating).
- New alerts are inserted with `status = 'OPEN'`.
- Alerts can be marked `RESOLVED` via `markResolved(id)`.

The alert database is shared with the Notifier process:

```
C:\ProgramData\CapabilityMonitor\alerts.db
```

---

## Output Files

| Path | Contents |
|---|---|
| `C:\ProgramData\CapabilityMonitor\alerts.db` | SQLite alert store (shared with Notifier) |
| `C:\ProgramData\CapabilityMonitor\snapshot.db` | Working snapshot of CapabilityAccessManager.db |
| `C:\ProgramData\CapabilityMonitor\log.txt` | Service log |

---

## Alerts Database Schema

```sql
CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    process       TEXT,
    type          TEXT,
    first_seen    INTEGER,   -- Unix timestamp
    last_seen     INTEGER,
    last_notified INTEGER,
    status        TEXT DEFAULT 'OPEN'   -- 'OPEN' | 'RESOLVED'
);
```

---

## Configuration Constants

All tuning constants are defined at the top of `detector.cpp`:

| Constant | Default | Meaning |
|---|---|---|
| `WINDOW_MS` | 28,800,000 (8 hours) | Sliding analysis window |
| `TIGHT_LOOP_GAP` | 50 ms | Max inter-event gap for tight loop detection |
| `TIGHT_LOOP_MIN` | 15 | Min consecutive events to trigger tight loop |
| `BURST_RATE_MIN` | 50 events/sec | Peak rate threshold for burst detection |
| `STEADY_RATE_MIN` | 15.0 events/sec | Average rate threshold for steady loop |
| `BASELINE_MULT` | 2.0× | Multiplier over baseline to flag as anomaly |
| `PERIODIC_COV` | 0.10 | Max coefficient of variation for periodic detection |
| `MIN_EVENTS` | 10 | Minimum events required after windowing |
| `MIN_EVENTS_FULL` | 20 | Minimum events required before windowing |

---

## Dependencies

- **SQLite3** — database snapshot and alert storage
- **Windows Service API** (`windows.h`) — service lifecycle management

---

## Building

The project targets Windows and requires:

- MSVC (Visual Studio 2019+ recommended)
- SQLite3 headers and library
- C++17 or later (`std::filesystem`, structured bindings)

Install the service:

```
sc create CapabilityMonitor binPath= "C:\Path\To\CapabilityMonitor.exe" start= auto
sc start CapabilityMonitor
```

---

## Related Project

**CapabilityMonitor Notifier** — a companion tray application that polls `alerts.db`, delivers Windows toast notifications for open alerts, and lets the user resolve them with a single click. See `README.md - CapabilityMonitorNotifier`.
