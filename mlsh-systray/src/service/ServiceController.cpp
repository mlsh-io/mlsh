#include "service/ServiceController.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>

#ifdef Q_OS_WIN
#  include <windows.h>
#  include <winsvc.h>
#  include <shellapi.h>
#endif

namespace ServiceController {

QString stateLabel(State state)
{
    switch (state) {
    case State::NotInstalled:
        return QObject::tr("Not installed");
    case State::Stopped:
        return QObject::tr("Stopped");
    case State::Running:
        return QObject::tr("Running");
    case State::StartPending:
        return QObject::tr("Starting…");
    case State::StopPending:
        return QObject::tr("Stopping…");
    case State::Unsupported:
        return QObject::tr("Unsupported");
    case State::Unknown:
        break;
    }
    return QObject::tr("Unknown");
}

QString mlshBinaryPath()
{
    const QString dir = QCoreApplication::applicationDirPath();
    const QFileInfo fi(QDir(dir).filePath(QStringLiteral("mlsh.exe")));
    return fi.exists() ? fi.absoluteFilePath() : QString();
}

#ifdef Q_OS_WIN

static const wchar_t *kServiceName = L"mlshtund";

State queryState()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return State::Unknown;

    State result = State::Unknown;
    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS);
    if (!svc) {
        const DWORD err = GetLastError();
        result = (err == ERROR_SERVICE_DOES_NOT_EXIST) ? State::NotInstalled
                                                        : State::Unknown;
        CloseServiceHandle(scm);
        return result;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
        switch (ssp.dwCurrentState) {
        case SERVICE_RUNNING:
            result = State::Running;
            break;
        case SERVICE_STOPPED:
            result = State::Stopped;
            break;
        case SERVICE_START_PENDING:
        case SERVICE_CONTINUE_PENDING:
            result = State::StartPending;
            break;
        case SERVICE_STOP_PENDING:
        case SERVICE_PAUSE_PENDING:
        case SERVICE_PAUSED:
            result = State::StopPending;
            break;
        default:
            result = State::Unknown;
            break;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return result;
}

/// Launch `file params` with the UAC "runas" verb. Fire-and-forget.
static bool runElevated(const QString &file, const QString &params, QString *error)
{
    const std::wstring wfile = file.toStdWString();
    const std::wstring wparams = params.toStdWString();

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"runas";
    sei.lpFile = wfile.c_str();
    sei.lpParameters = wparams.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        const DWORD err = GetLastError();
        if (error) {
            *error = (err == ERROR_CANCELLED)
                ? QObject::tr("Elevation was cancelled")
                : QObject::tr("Failed to launch elevated command (error %1)").arg(err);
        }
        return false;
    }
    return true;
}

bool install(QString *error)
{
    const QString mlsh = mlshBinaryPath();
    if (mlsh.isEmpty()) {
        if (error)
            *error = QObject::tr("mlsh.exe not found next to the app");
        return false;
    }
    return runElevated(mlsh, QStringLiteral("tunnel install"), error);
}

bool uninstall(QString *error)
{
    const QString mlsh = mlshBinaryPath();
    if (mlsh.isEmpty()) {
        if (error)
            *error = QObject::tr("mlsh.exe not found next to the app");
        return false;
    }
    return runElevated(mlsh, QStringLiteral("tunnel uninstall"), error);
}

bool start(QString *error)
{
    return runElevated(QStringLiteral("sc.exe"), QStringLiteral("start mlshtund"), error);
}

bool stop(QString *error)
{
    return runElevated(QStringLiteral("sc.exe"), QStringLiteral("stop mlshtund"), error);
}

#else // !Q_OS_WIN — stub for the future Linux port

State queryState()
{
    return State::Unsupported;
}

bool install(QString *error)
{
    if (error)
        *error = QObject::tr("Service control is only implemented on Windows");
    return false;
}
bool uninstall(QString *error) { return install(error); }
bool start(QString *error) { return install(error); }
bool stop(QString *error) { return install(error); }

#endif

} // namespace ServiceController
