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
3. Each run checks the database and WAL metadata. Unchanged sources are skipped; changed sources are snapshotted and analyzed.
4. Baselines are loaded once at service start and atomically saved after each monitoring window instead of every 5-second pass.
5. The service then sleeps until the next hour boundary.

---

## Architecture

```
service_main.cpp
    └── RunMonitoringWindow()          every hour, 5-min window
            └── RunDetector()          every 5 seconds
                    ├── backupDatabase()       snapshot.cpp  — SQLite online backup
                    ├── readEvents()           analyzer.h    — parse events from snapshot
                    └── detectLoops()          detector.cpp  — metrics & orchestration
                            ├── DetectionEngine          detector_pipeline.cpp
                            │       └── six ordered detector modules
                            ├── scoreFindings()          risk_scoring.cpp
                            ├── loadBaseline() / saveBaseline()   baseline.h
                            └── handleAlert()                     alert_manager.cpp
```

### Components

| File | Responsibility |
|---|---|
| `service_main.cpp` | Windows Service entry point, control handler, hourly scheduling |
| `detector.cpp` | Computes process timing metrics and orchestrates detection, baseline learning, logging, and alerts |
| `detector_pipeline.h/cpp` | C++17 detector contract, six stateless detector modules, and deterministic `DetectionEngine` |
| `risk_scoring.h/cpp` | Aggregates ordered findings into scoring version 1, severity, confidence, and legacy type |
| `analyzer.h` | `Event` struct + `readEvents()` — reads raw events from DB snapshot |
| `baseline.h/cpp` | Persists per-process average rates across runs for anomaly detection |
| `alert_manager.cpp` | SQLite-backed alert store with deduplication and hourly reminders |
| `snapshot.cpp` | Safe read-only backup of the live CapabilityAccessManager DB |
| `logger.cpp` | Thread-safe append logger → `C:\ProgramData\CapabilityMonitor\log.txt` |
| `utils.cpp` | FILETIME → milliseconds conversion |

---

## Detection Logic

All detection operates within an 8-hour sliding window anchored to the current time. A minimum of 10 valid events is required before classification.

| Alert Type | Condition |
|---|---|
| `TIGHT LOOP` | 15+ consecutive launches with < 50 ms between them |
| `BURST LOOP` | Peak rate > 50 events/sec within any 1-second window |
| `STEADY LOOP` | Long-run average rate > 15 events/sec |
| `BASELINE ANOMALY` | Current average rate > 2× the process's historical baseline |
| `PERIODIC` | Inter-event gap coefficient of variation < 10% (highly regular timing) |
| `HIGH ACTIVITY` | More than 50 events recorded in the window |

Multiple findings can be raised simultaneously for a process. Six stateless detector modules run through `DetectionEngine` in the fixed order shown above. That order is a compatibility contract for the legacy type string, normalized finding rows, and evidence JSON. Findings are combined by scoring policy version 1 into a 0–100 risk score.

### Risk scoring version 1

| Finding | Score contribution |
|---|---:|
| `TIGHT LOOP` | 30 |
| `BURST LOOP` | 30 |
| `STEADY LOOP` | 25 |
| `BASELINE ANOMALY` | 25 |
| `PERIODIC` | 10 |
| `HIGH ACTIVITY` | 10 |

The score is capped at 100. Severity bands are: `INFORMATIONAL` 0–19, `LOW` 20–39, `MEDIUM` 40–59, `HIGH` 60–79, and `CRITICAL` 80–100. Confidence increases with event count and baseline maturity and is reduced when no historical baseline exists.

---

## Alert Deduplication

`alert_manager.cpp` prevents alert spam:

- Open-alert identity is `(full binary path, alert type)`, preventing collisions between same-named executables and different classifications.
- Repeated alerts update `last_seen` and observation metrics. Equal or stronger results replace the stored score, confidence, explanation JSON, and normalized findings; weaker results do not lower or overwrite the strongest evidence.
- A reminder log entry is written at most once per hour (`last_notified` gating).
- Existing databases are migrated in place and retain all notifier-compatible columns.
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
    status           TEXT DEFAULT 'OPEN',  -- 'OPEN' | 'RESOLVED'
    process_path     TEXT NOT NULL DEFAULT '',
    risk_score       INTEGER NOT NULL DEFAULT 0,
    severity         TEXT NOT NULL DEFAULT 'INFORMATIONAL',
    confidence       INTEGER NOT NULL DEFAULT 0,
    scoring_version  INTEGER NOT NULL DEFAULT 0,
    event_count      INTEGER NOT NULL DEFAULT 0,
    peak_rate        INTEGER NOT NULL DEFAULT 0,
    average_rate     REAL NOT NULL DEFAULT 0,
    baseline_rate    REAL NOT NULL DEFAULT 0,
    first_event_time INTEGER NOT NULL DEFAULT 0,
    last_event_time  INTEGER NOT NULL DEFAULT 0,
    reason_json      TEXT NOT NULL DEFAULT '{}'
);

-- Schema version 3 retains all legacy notifier columns and adds normalized
-- alert_findings and alert_evidence tables with deterministic ordering.
```

---

## Configuration Constants

Metric/window constants are defined in `detector.cpp`; classification thresholds and version 1 score contributions are owned by `detector_pipeline.cpp`:

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
| `MIN_EVENTS_FULL` | 10 | Minimum valid events required before windowing |

---

## Dependencies

- **SQLite3** — database snapshot and alert storage
- **Windows Service API** (`windows.h`) — service lifecycle management

---

## Building

The project targets Windows and requires:

- MSVC (Visual Studio 2019+ recommended)
- SQLite3 headers and library
- C++17 (`std::filesystem`, structured bindings)

CMake now builds a reusable core plus `CapabilityMonitorTests`. Configure it out of source with a discoverable SQLite3 package:

```text
cmake -S CapabilityAccessManagerMonitor -B build -DBUILD_TESTING=ON
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

The Visual Studio project still requires a local SQLite/SQLCipher include and import-library setup; do not assume the checked-in runtime DLLs provide compile-time linkage.

Install the service:

```
sc create CapabilityMonitor binPath= "C:\Path\To\CapabilityMonitor.exe" start= auto
sc start CapabilityMonitor
```

---

## Related Project

**CapabilityMonitor Notifier** — a companion tray application that polls `alerts.db`, delivers Windows toast notifications for open alerts, and lets the user resolve them with a single click. See `README.md - CapabilityMonitorNotifier`.
