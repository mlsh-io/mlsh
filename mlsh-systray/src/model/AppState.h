#pragma once

#include "ipc/Protocol.h"
#include "model/TunnelStatus.h"
#include "service/ServiceController.h"
#include "update/UpdateChecker.h"

#include <QByteArray>
#include <QObject>
#include <QQueue>
#include <QSet>
#include <QString>
#include <QStringList>
#include <functional>
#include <optional>

class DaemonClient;
class QTimer;

/// Central observable state for the systray app (parity with the macOS
/// AppState). Owns the daemon client, a serialized request queue, and the
/// polling timers. UI widgets connect to changed()/message() and re-read the
/// accessors.
class AppState : public QObject
{
    Q_OBJECT
public:
    enum class OverallState {
        Connected,    // all tunnels connected
        Partial,      // some connected
        Disconnected, // none / all down, but daemon reachable
        DaemonDown,   // can't reach mlshtund
    };

    explicit AppState(QObject *parent = nullptr);

    void start(); // begin polling

    // --- Accessors ---
    const QList<mlsh::TunnelStatus> &tunnels() const { return m_tunnels; }
    QStringList availableClusters() const { return m_availableClusters; }
    QStringList disconnectedClusters() const;
    bool daemonReachable() const { return m_daemonReachable; }
    OverallState overallState() const;
    QString statusText() const;
    QString appVersion() const { return m_appVersion; }
    bool isClusterBusy(const QString &cluster) const { return m_busyClusters.contains(cluster); }

    ServiceController::State serviceState() const { return m_serviceState; }

    bool hasUpdate() const { return m_update.has_value(); }
    UpdateChecker::Release update() const { return m_update.value_or(UpdateChecker::Release{}); }

    // --- Actions ---
    void connectCluster(const QString &cluster);
    void disconnectCluster(const QString &cluster);
    void refreshNow();           // poll status immediately
    void refreshServiceState();  // re-query the Windows service

signals:
    void changed();                  // any state changed; redraw UI
    void message(const QString &text); // transient toast / status-bar text

private:
    using ResponseHandler =
        std::function<void(bool ok, const mlsh::DaemonResponse &, const QString &err)>;

    void poll();
    void enqueue(const QByteArray &payload, ResponseHandler handler);
    void pump();
    void onClientFinished(const mlsh::DaemonResponse &resp);
    void onClientFailed(const QString &err);

    int connectedCount() const;
    static QString detectAppVersion();

    DaemonClient *m_client = nullptr;
    QTimer *m_pollTimer = nullptr;
    QTimer *m_serviceTimer = nullptr;
    UpdateChecker *m_updateChecker = nullptr;

    QList<mlsh::TunnelStatus> m_tunnels;
    QStringList m_availableClusters;
    bool m_daemonReachable = false;
    QSet<QString> m_busyClusters;
    ServiceController::State m_serviceState = ServiceController::State::Unknown;
    QString m_appVersion;
    std::optional<UpdateChecker::Release> m_update;

    QQueue<QPair<QByteArray, ResponseHandler>> m_queue;
    ResponseHandler m_currentHandler;
};
