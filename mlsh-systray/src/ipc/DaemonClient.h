#pragma once

#include "ipc/Protocol.h"

#include <QByteArray>
#include <QObject>
#include <QStringList>

class QLocalSocket;
class QTimer;

/// Talks to the mlshtund daemon over its control endpoint.
///
/// On Windows the endpoint is a named pipe; Qt's QLocalSocket maps the server
/// name "mlshtund" to `\\.\pipe\mlshtund`. We try the system pipe first, then
/// the per-user pipe, mirroring the Rust client's `connect_default`.
///
/// One request is handled at a time: connect → write framed JSON → read framed
/// JSON → close. Callers should serialize requests (AppState does).
class DaemonClient : public QObject
{
    Q_OBJECT
public:
    explicit DaemonClient(QObject *parent = nullptr);
    ~DaemonClient() override;

    bool isBusy() const { return m_busy; }

    /// Send a JSON request body (from Protocol::build*). Emits finished() with
    /// the parsed response, or failed() if no endpoint answered / framing broke.
    void send(const QByteArray &jsonBody);

signals:
    void finished(const mlsh::DaemonResponse &response);
    void failed(const QString &error);

private slots:
    void onConnected();
    void onReadyRead();
    void onErrorOccurred();

private:
    void tryEndpoint(int index);
    void resetSocket();
    void emitFinished(const mlsh::DaemonResponse &response);
    void emitFailed(const QString &error);

    static QStringList defaultEndpoints();

    QLocalSocket *m_socket = nullptr;
    QTimer *m_timeout = nullptr;
    QStringList m_endpoints;
    int m_endpointIndex = 0;
    QByteArray m_request;  // framed bytes pending write
    QByteArray m_inbuf;    // accumulated response bytes
    bool m_busy = false;
};
