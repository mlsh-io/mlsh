#include "ui/TrayIcon.h"

#include "model/AppState.h"
#include "service/ServiceController.h"
#include "ui/IconFactory.h"

#include <QApplication>
#include <QMenu>
#include <QSystemTrayIcon>
#include <QTimer>

TrayIcon::TrayIcon(AppState *state, QObject *parent)
    : QObject(parent)
    , m_state(state)
    , m_tray(new QSystemTrayIcon(this))
    , m_menu(new QMenu)
{
    m_tray->setContextMenu(m_menu);

    connect(m_tray, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::Trigger
                    || reason == QSystemTrayIcon::DoubleClick) {
                    emit showWindowRequested();
                }
            });

    connect(m_state, &AppState::changed, this, &TrayIcon::refresh);
    refresh();
}

void TrayIcon::show()
{
    m_tray->show();
}

void TrayIcon::refresh()
{
    const AppState::OverallState os = m_state->overallState();
    m_tray->setIcon(IconFactory::trayIcon(os));
    m_tray->setToolTip(QStringLiteral("MLSH — %1").arg(m_state->statusText()));
    rebuildMenu();
}

void TrayIcon::rebuildMenu()
{
    m_menu->clear();

    QAction *open = m_menu->addAction(tr("Open MLSH"));
    connect(open, &QAction::triggered, this, &TrayIcon::showWindowRequested);

    QAction *adopt = m_menu->addAction(tr("Adopt a tunnel…"));
    connect(adopt, &QAction::triggered, this, &TrayIcon::adoptRequested);
    QAction *create = m_menu->addAction(tr("New tunnel…"));
    connect(create, &QAction::triggered, this, &TrayIcon::createRequested);
    m_menu->addSeparator();

    // Connected tunnels → disconnect.
    for (const mlsh::TunnelStatus &t : m_state->tunnels()) {
        const QString cluster = t.cluster;
        QAction *a = m_menu->addAction(tr("Disconnect %1").arg(cluster));
        a->setEnabled(!m_state->isClusterBusy(cluster));
        connect(a, &QAction::triggered, m_state,
                [this, cluster]() { m_state->disconnectCluster(cluster); });
    }
    // Disconnected clusters → connect.
    for (const QString &cluster : m_state->disconnectedClusters()) {
        QAction *a = m_menu->addAction(tr("Connect %1").arg(cluster));
        a->setEnabled(!m_state->isClusterBusy(cluster));
        connect(a, &QAction::triggered, m_state,
                [this, cluster]() { m_state->connectCluster(cluster); });
    }

    // Service submenu (Windows only).
    using S = ServiceController::State;
    const S svc = m_state->serviceState();
    if (svc != S::Unsupported) {
        m_menu->addSeparator();
        QMenu *svcMenu = m_menu->addMenu(
            tr("Service: %1").arg(ServiceController::stateLabel(svc)));

        auto addSvc = [this, svcMenu](const QString &label, bool enabled,
                                      bool (*action)(QString *)) {
            QAction *a = svcMenu->addAction(label);
            a->setEnabled(enabled);
            connect(a, &QAction::triggered, this, [this, action]() {
                QString err;
                if (action(&err))
                    QTimer::singleShot(1500, m_state, &AppState::refreshServiceState);
            });
        };
        addSvc(tr("Install"), svc == S::NotInstalled, &ServiceController::install);
        addSvc(tr("Uninstall"), svc == S::Stopped || svc == S::Running,
               &ServiceController::uninstall);
        addSvc(tr("Start"), svc == S::Stopped, &ServiceController::start);
        addSvc(tr("Stop"), svc == S::Running, &ServiceController::stop);
    }

    m_menu->addSeparator();
    QAction *quit = m_menu->addAction(tr("Quit"));
    connect(quit, &QAction::triggered, this, &TrayIcon::quitRequested);
}
