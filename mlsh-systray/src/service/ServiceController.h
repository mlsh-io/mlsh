#pragma once

#include <QString>

/// Controls the `mlshtund` Windows service.
///
/// - queryState() reads the SCM read-only (no elevation required).
/// - install()/uninstall()/start()/stop() launch an elevated helper via UAC
///   (ShellExecuteEx "runas"). They are fire-and-forget: the caller should
///   re-query the state shortly after (AppState polls it on a timer).
///
/// On non-Windows platforms this is a stub returning Unsupported so the rest of
/// the app builds and runs (Linux/systemd support comes later).
namespace ServiceController {

enum class State {
    NotInstalled,
    Stopped,
    Running,
    StartPending,
    StopPending,
    Unsupported, // non-Windows, or SCM unavailable
    Unknown,
};

QString stateLabel(State state);

/// Read-only query of the service state. Cheap; safe to poll.
State queryState();

/// Path to mlsh.exe, expected next to this executable. Empty if not found.
QString mlshBinaryPath();

/// Launch `mlsh tunnel install` elevated. Returns false if the launch could
/// not be started (e.g. user declined the UAC prompt, or mlsh.exe missing).
bool install(QString *error = nullptr);
/// Launch `mlsh tunnel uninstall` elevated.
bool uninstall(QString *error = nullptr);
/// Launch `sc.exe start mlshtund` elevated.
bool start(QString *error = nullptr);
/// Launch `sc.exe stop mlshtund` elevated.
bool stop(QString *error = nullptr);

} // namespace ServiceController
