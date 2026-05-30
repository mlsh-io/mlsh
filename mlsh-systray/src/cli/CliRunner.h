#pragma once

#include <QByteArray>
#include <QJsonValue>
#include <QObject>
#include <QString>
#include <QStringList>

class QProcess;

/// Runs `mlsh.exe` (deployed next to the app) as a child process.
///
/// Two modes:
///  - runJson(): prepends `--json`, parses the standard envelope
///    ({"ok":true,"data":…} / {"ok":false,"error":…}) and emits jsonFinished().
///    The instance deletes itself after finishing.
///  - runStreaming(): no `--json` (human output); streams stdout/stderr lines via
///    outputLine() and ends with streamFinished(). Used for the managed `setup`
///    device flow, which is not available in JSON mode. cancel() kills it.
///
/// All invocations run unelevated with no console window (CREATE_NO_WINDOW).
class CliRunner : public QObject
{
    Q_OBJECT
public:
    struct Result {
        bool launched = false; // process actually started
        bool ok = false;       // envelope "ok" (or exit==0 fallback)
        int exitCode = -1;
        QJsonValue data;       // envelope "data" when ok
        QString error;         // envelope "error" / stderr on failure
    };

    explicit CliRunner(QObject *parent = nullptr);

    /// Run `mlsh --json <args>`; emits jsonFinished() then self-destructs.
    void runJson(const QStringList &args, const QByteArray &stdinData = {});

    /// Run `mlsh <args>` (human output), streaming lines. Does NOT self-destruct.
    void runStreaming(const QStringList &args);
    void cancel();

signals:
    void jsonFinished(const CliRunner::Result &result);
    void outputLine(const QString &line);
    void streamFinished(int exitCode);

private:
    QProcess *makeProcess();
    static QString mlshPath();

    QProcess *m_proc = nullptr;
    QByteArray m_stdinData;
    QString m_lineBuf;
};
