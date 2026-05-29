#include "ipc/DaemonClient.h"

#include <QLocalSocket>
#include <QTimer>
#include <QtEndian>

namespace {
constexpr int kRequestTimeoutMs = 4000;
constexpr quint32 kMaxMsgSize = 1024 * 1024; // matches MAX_MSG_SIZE in protocol.rs
} // namespace

DaemonClient::DaemonClient(QObject *parent)
    : QObject(parent)
{
    m_timeout = new QTimer(this);
    m_timeout->setSingleShot(true);
    m_timeout->setInterval(kRequestTimeoutMs);
    connect(m_timeout, &QTimer::timeout, this, [this]() {
        emitFailed(QStringLiteral("Timed out waiting for the mlshtund daemon"));
    });
}

DaemonClient::~DaemonClient()
{
    resetSocket();
}

QStringList DaemonClient::defaultEndpoints()
{
#ifdef Q_OS_WIN
    // System pipe (daemon as a LocalSystem service), then the per-user pipe
    // (daemon running in a console). Qt prepends \\.\pipe\ to the server name.
    QStringList eps;
    eps << QStringLiteral("mlshtund");

    QString user = qEnvironmentVariable("USERNAME");
    if (user.isEmpty())
        user = QStringLiteral("user");
    // Mirror sanitize_pipe_segment(): keep [A-Za-z0-9_-], replace the rest.
    QString sanitized;
    sanitized.reserve(user.size());
    for (QChar c : user) {
        const ushort u = c.unicode();
        const bool ok = (u >= '0' && u <= '9') || (u >= 'A' && u <= 'Z')
            || (u >= 'a' && u <= 'z') || c == QLatin1Char('-') || c == QLatin1Char('_');
        sanitized.append(ok ? c : QLatin1Char('_'));
    }
    eps << QStringLiteral("mlshtund-%1").arg(sanitized);
    return eps;
#else
    // Future Linux/macOS port: QLocalSocket connects to a Unix socket path.
    QStringList eps;
#if defined(Q_OS_LINUX)
    eps << QStringLiteral("/run/mlsh/mlshtund.sock");
#else
    eps << QStringLiteral("/var/run/mlsh/mlshtund.sock");
#endif
    const QString home = qEnvironmentVariable("HOME");
    if (!home.isEmpty())
        eps << home + QStringLiteral("/.config/mlsh/mlshtund.sock");
    return eps;
#endif
}

void DaemonClient::send(const QByteArray &jsonBody)
{
    if (m_busy) {
        emit failed(QStringLiteral("DaemonClient is busy"));
        return;
    }
    m_busy = true;
    m_inbuf.clear();

    // Frame: 4-byte big-endian length + body.
    m_request.clear();
    m_request.resize(4);
    qToBigEndian<quint32>(static_cast<quint32>(jsonBody.size()),
                          reinterpret_cast<uchar *>(m_request.data()));
    m_request.append(jsonBody);

    m_endpoints = defaultEndpoints();
    m_endpointIndex = 0;
    tryEndpoint(0);
}

void DaemonClient::tryEndpoint(int index)
{
    resetSocket();

    if (index >= m_endpoints.size()) {
        emitFailed(QStringLiteral("mlshtund is not running"));
        return;
    }
    m_endpointIndex = index;

    m_socket = new QLocalSocket(this);
    connect(m_socket, &QLocalSocket::connected, this, &DaemonClient::onConnected);
    connect(m_socket, &QLocalSocket::readyRead, this, &DaemonClient::onReadyRead);
    connect(m_socket, &QLocalSocket::errorOccurred, this, &DaemonClient::onErrorOccurred);

    m_timeout->start();
    m_socket->connectToServer(m_endpoints.at(index));
}

void DaemonClient::onConnected()
{
    if (!m_socket)
        return;
    m_socket->write(m_request);
    m_socket->flush();
}

void DaemonClient::onReadyRead()
{
    if (!m_socket)
        return;
    m_inbuf.append(m_socket->readAll());

    if (m_inbuf.size() < 4)
        return; // need the length prefix

    const quint32 len = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(m_inbuf.constData()));
    if (len > kMaxMsgSize) {
        emitFailed(QStringLiteral("Response too large (%1 bytes)").arg(len));
        return;
    }
    if (static_cast<quint32>(m_inbuf.size()) < 4 + len)
        return; // wait for the rest of the body

    const QByteArray body = m_inbuf.mid(4, static_cast<int>(len));
    const mlsh::DaemonResponse resp = mlsh::parseResponse(body);
    if (!resp.parsed) {
        emitFailed(QStringLiteral("Malformed response from daemon"));
        return;
    }
    emitFinished(resp);
}

void DaemonClient::onErrorOccurred()
{
    // The current endpoint failed to connect (or dropped). Try the next one.
    // Avoid retrying once we've already started receiving a response.
    if (m_inbuf.isEmpty()) {
        tryEndpoint(m_endpointIndex + 1);
    } else {
        emitFailed(QStringLiteral("Connection to daemon dropped"));
    }
}

void DaemonClient::emitFinished(const mlsh::DaemonResponse &response)
{
    m_timeout->stop();
    resetSocket();
    m_busy = false;
    emit finished(response);
}

void DaemonClient::emitFailed(const QString &error)
{
    m_timeout->stop();
    resetSocket();
    m_busy = false;
    emit failed(error);
}

void DaemonClient::resetSocket()
{
    if (m_socket) {
        m_socket->disconnect(this);
        m_socket->abort();
        m_socket->deleteLater();
        m_socket = nullptr;
    }
}
