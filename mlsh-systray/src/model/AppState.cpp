#include "model/AppState.h"

#include "config/ClusterDiscovery.h"
#include "ipc/DaemonClient.h"

#include <QProcess>
#include <QSet>
#include <QTimer>

namespace {
constexpr int kPollIntervalMs = 3000;
constexpr int kServiceIntervalMs = 4000;
constexpr int kUpdateIntervalMs = 6 * 3600 * 1000; // 6h
} // namespace

AppState::AppState(QObject *parent)
    : QObject(parent)
    , m_client(new DaemonClient(this))
    , m_pollTimer(new QTimer(this))
    , m_serviceTimer(new QTimer(this))
    , m_updateChecker(new UpdateChecker(this))
{
    m_appVersion = detectAppVersion();

    connect(m_client, &DaemonClient::finished, this, &AppState::onClientFinished);
    connect(m_client, &DaemonClient::failed, this, &AppState::onClientFailed);

    m_pollTimer->setInterval(kPollIntervalMs);
    connect(m_pollTimer, &QTimer::timeout, this, &AppState::poll);

    m_serviceTimer->setInterval(kServiceIntervalMs);
    connect(m_serviceTimer, &QTimer::timeout, this, &AppState::refreshServiceState);

    connect(m_updateChecker, &UpdateChecker::updateAvailable, this,
            [this](const UpdateChecker::Release &rel) {
                m_update = rel;
                emit changed();
            });
}

void AppState::start()
{
    refreshServiceState();
    poll();
    m_pollTimer->start();
    m_serviceTimer->start();

    // Check for updates now, then every 6 hours.
    m_updateChecker->check(m_appVersion);
    auto *updateTimer = new QTimer(this);
    updateTimer->setInterval(kUpdateIntervalMs);
    connect(updateTimer, &QTimer::timeout, this,
            [this]() { m_updateChecker->check(m_appVersion); });
    updateTimer->start();
}

QString AppState::detectAppVersion()
{
    const QString mlsh = ServiceController::mlshBinaryPath();
    if (mlsh.isEmpty())
        return QStringLiteral("dev");

    QProcess p;
    p.start(mlsh, {QStringLiteral("--version")});
    if (!p.waitForFinished(3000))
        return QStringLiteral("dev");

    const QString out = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
    // Typically "mlsh 0.3.0-g68c6b6c".
    if (out.startsWith(QStringLiteral("mlsh ")))
        return out.mid(5);
    return out.isEmpty() ? QStringLiteral("dev") : out;
}

int AppState::connectedCount() const
{
    int n = 0;
    for (const auto &t : m_tunnels)
        if (t.state == mlsh::TunnelState::Connected)
            ++n;
    return n;
}

AppState::OverallState AppState::overallState() const
{
    if (!m_daemonReachable)
        return OverallState::DaemonDown;
    const int connected = connectedCount();
    if (connected == 0)
        return OverallState::Disconnected;
    if (connected == m_tunnels.size())
        return OverallState::Connected;
    return OverallState::Partial;
}

QString AppState::statusText() const
{
    switch (overallState()) {
    case OverallState::Connected:
        return m_tunnels.size() == 1 ? tr("Connected")
                                     : tr("%1 connected").arg(m_tunnels.size());
    case OverallState::Partial:
        return tr("%1 of %2 connected").arg(connectedCount()).arg(m_tunnels.size());
    case OverallState::Disconnected:
        return tr("Disconnected");
    case OverallState::DaemonDown:
        return tr("Daemon not running");
    }
    return {};
}

QStringList AppState::disconnectedClusters() const
{
    QSet<QString> active;
    for (const auto &t : m_tunnels)
        active.insert(t.cluster);

    QStringList out;
    for (const QString &c : m_availableClusters)
        if (!active.contains(c))
            out << c;
    return out;
}

void AppState::refreshServiceState()
{
    const ServiceController::State s = ServiceController::queryState();
    if (s != m_serviceState) {
        m_serviceState = s;
        emit changed();
    }
}

void AppState::refreshNow()
{
    poll();
}

void AppState::poll()
{
    // Refresh the on-disk cluster list every tick (cheap directory scan).
    const QStringList clusters = ClusterDiscovery::availableClusters();
    if (clusters != m_availableClusters) {
        m_availableClusters = clusters;
        emit changed();
    }

    enqueue(mlsh::buildStatusRequest(),
            [this](bool ok, const mlsh::DaemonResponse &resp, const QString &) {
                if (ok && resp.type == mlsh::ResponseType::Status) {
                    m_tunnels = resp.tunnels;
                    m_daemonReachable = true;
                } else if (ok) {
                    // Reachable but returned ok/error to a status request.
                    m_daemonReachable = true;
                } else {
                    m_daemonReachable = false;
                    m_tunnels.clear();
                }
                emit changed();
            });
}

void AppState::connectCluster(const QString &cluster)
{
    QString configToml, certPem, keyPem, err;
    if (!ClusterDiscovery::readConnectMaterial(cluster, configToml, certPem, keyPem, err)) {
        emit message(err);
        return;
    }

    m_busyClusters.insert(cluster);
    emit changed();

    enqueue(mlsh::buildConnectRequest(cluster, configToml, certPem, keyPem),
            [this, cluster](bool ok, const mlsh::DaemonResponse &resp, const QString &error) {
                m_busyClusters.remove(cluster);
                if (!ok) {
                    emit message(error);
                } else if (resp.type == mlsh::ResponseType::Error) {
                    emit message(resp.message);
                } else if (resp.type == mlsh::ResponseType::Ok && !resp.message.isEmpty()) {
                    emit message(resp.message);
                }
                emit changed();
                refreshNow();
            });
}

void AppState::disconnectCluster(const QString &cluster)
{
    m_busyClusters.insert(cluster);
    emit changed();

    enqueue(mlsh::buildDisconnectRequest(cluster),
            [this, cluster](bool ok, const mlsh::DaemonResponse &resp, const QString &error) {
                m_busyClusters.remove(cluster);
                if (!ok) {
                    emit message(error);
                } else if (resp.type == mlsh::ResponseType::Error) {
                    emit message(resp.message);
                } else if (resp.type == mlsh::ResponseType::Ok && !resp.message.isEmpty()) {
                    emit message(resp.message);
                }
                emit changed();
                refreshNow();
            });
}

void AppState::enqueue(const QByteArray &payload, ResponseHandler handler)
{
    m_queue.enqueue({payload, std::move(handler)});
    pump();
}

void AppState::pump()
{
    if (m_client->isBusy() || m_queue.isEmpty())
        return;
    auto item = m_queue.dequeue();
    m_currentHandler = std::move(item.second);
    m_client->send(item.first);
}

void AppState::onClientFinished(const mlsh::DaemonResponse &resp)
{
    ResponseHandler h = std::move(m_currentHandler);
    m_currentHandler = nullptr;
    if (h)
        h(true, resp, QString());
    pump();
}

void AppState::onClientFailed(const QString &err)
{
    ResponseHandler h = std::move(m_currentHandler);
    m_currentHandler = nullptr;
    if (h)
        h(false, mlsh::DaemonResponse{}, err);
    pump();
}
