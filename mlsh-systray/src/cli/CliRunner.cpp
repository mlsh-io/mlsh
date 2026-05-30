#include "cli/CliRunner.h"

#include "service/ServiceController.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>

#ifdef Q_OS_WIN
#  include <windows.h>
#endif

CliRunner::CliRunner(QObject *parent)
    : QObject(parent)
{
}

QString CliRunner::mlshPath()
{
    return ServiceController::mlshBinaryPath();
}

QProcess *CliRunner::makeProcess()
{
    auto *proc = new QProcess(this);
#ifdef Q_OS_WIN
    // mlsh.exe is a console app; don't flash a console window from the GUI.
    proc->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
        args->flags |= CREATE_NO_WINDOW;
    });
#endif
    return proc;
}

void CliRunner::runJson(const QStringList &args, const QByteArray &stdinData)
{
    const QString mlsh = mlshPath();
    if (mlsh.isEmpty()) {
        Result r;
        r.error = tr("mlsh.exe not found next to the app");
        emit jsonFinished(r);
        deleteLater();
        return;
    }

    m_proc = makeProcess();
    m_stdinData = stdinData;

    connect(m_proc, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        Result r;
        r.error = m_proc ? m_proc->errorString() : tr("failed to start mlsh");
        emit jsonFinished(r);
        deleteLater();
    });

    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this](int exitCode, QProcess::ExitStatus) {
                Result r;
                r.launched = true;
                r.exitCode = exitCode;

                const QByteArray out = m_proc->readAllStandardOutput();
                const QByteArray err = m_proc->readAllStandardError();

                QJsonParseError pe{};
                const QJsonDocument doc = QJsonDocument::fromJson(out.trimmed(), &pe);
                if (doc.isObject()) {
                    const QJsonObject o = doc.object();
                    r.ok = o.value(QStringLiteral("ok")).toBool(false);
                    if (r.ok)
                        r.data = o.value(QStringLiteral("data"));
                    else
                        r.error = o.value(QStringLiteral("error")).toString();
                } else {
                    // Not JSON (unexpected) — fall back to exit code + stderr.
                    r.ok = (exitCode == 0);
                    QString msg = QString::fromUtf8(err).trimmed();
                    if (msg.isEmpty())
                        msg = QString::fromUtf8(out).trimmed();
                    if (!r.ok && msg.isEmpty())
                        msg = tr("command failed (exit %1)").arg(exitCode);
                    r.error = msg;
                }
                emit jsonFinished(r);
                deleteLater();
            });

    QStringList full;
    full << QStringLiteral("--json") << args;
    m_proc->start(mlsh, full);
    if (!m_stdinData.isEmpty()) {
        m_proc->write(m_stdinData);
    }
    m_proc->closeWriteChannel();
}

void CliRunner::runStreaming(const QStringList &args)
{
    const QString mlsh = mlshPath();
    if (mlsh.isEmpty()) {
        emit outputLine(tr("Error: mlsh.exe not found next to the app"));
        emit streamFinished(-1);
        return;
    }

    m_proc = makeProcess();
    m_proc->setProcessChannelMode(QProcess::MergedChannels);

    connect(m_proc, &QProcess::readyRead, this, [this]() {
        m_lineBuf += QString::fromUtf8(m_proc->readAll());
        int nl;
        while ((nl = m_lineBuf.indexOf(QLatin1Char('\n'))) >= 0) {
            QString line = m_lineBuf.left(nl);
            m_lineBuf.remove(0, nl + 1);
            line.remove(QLatin1Char('\r'));
            emit outputLine(line);
        }
    });
    connect(m_proc, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        emit outputLine(tr("Error: %1").arg(m_proc ? m_proc->errorString() : tr("process error")));
    });
    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this](int exitCode, QProcess::ExitStatus) {
                if (!m_lineBuf.isEmpty()) {
                    emit outputLine(m_lineBuf);
                    m_lineBuf.clear();
                }
                emit streamFinished(exitCode);
            });

    m_proc->start(mlsh, args);
    m_proc->closeWriteChannel();
}

void CliRunner::cancel()
{
    if (m_proc && m_proc->state() != QProcess::NotRunning) {
        m_proc->kill();
    }
}
