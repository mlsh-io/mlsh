#include "ui/MainWindow.h"

#include "config/ClusterDiscovery.h"
#include "model/AppState.h"
#include "service/ServiceController.h"
#include "ui/AdoptDialog.h"
#include "ui/CreateTunnelDialog.h"
#include "ui/IconFactory.h"
#include "ui/InviteDialog.h"
#include "ui/NodesDialog.h"
#include "ui/Theme.h"
#include "ui/TunnelRow.h"

#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QCursor>
#include <QDesktopServices>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QMenu>
#include <QMessageBox>
#include <QScrollArea>
#include <QStatusBar>
#include <QStyle>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

namespace {

QFrame *hLine()
{
    auto *line = new QFrame;
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    return line;
}

void clearLayout(QLayout *layout)
{
    if (!layout)
        return;
    while (QLayoutItem *item = layout->takeAt(0)) {
        if (QWidget *w = item->widget())
            w->deleteLater();
        if (QLayout *child = item->layout())
            clearLayout(child);
        delete item;
    }
}

QLabel *sectionHeader(const QString &text)
{
    auto *l = new QLabel(text);
    QFont f = l->font();
    f.setBold(true);
    f.setPointSizeF(f.pointSizeF() - 1);
    l->setFont(f);
    l->setStyleSheet(QStringLiteral("color: palette(mid);"));
    return l;
}

} // namespace

MainWindow::MainWindow(AppState *state, QWidget *parent)
    : QMainWindow(parent)
    , m_state(state)
{
    setWindowTitle(QStringLiteral("MLSH"));
    setWindowIcon(IconFactory::appIcon());
    resize(520, 600);
    setMinimumWidth(480);
    buildUi();

    connect(m_state, &AppState::changed, this, &MainWindow::refresh);
    connect(m_state, &AppState::message, this,
            [this](const QString &text) { statusBar()->showMessage(text, 5000); });

    refresh();
}

void MainWindow::buildUi()
{
    auto *central = new QWidget;
    auto *outer = new QVBoxLayout(central);
    outer->setContentsMargins(Theme::Spacing::Lg, Theme::Spacing::Lg,
                              Theme::Spacing::Lg, Theme::Spacing::Md);
    outer->setSpacing(Theme::Spacing::Md);

    // --- Header ---
    auto *header = new QHBoxLayout;
    header->setSpacing(Theme::Spacing::Sm);
    m_statusDot = new QLabel;
    m_statusDot->setFixedSize(12, 12);
    header->addWidget(m_statusDot);

    auto *title = new QLabel(QStringLiteral("MLSH"));
    QFont tf = title->font();
    tf.setBold(true);
    tf.setPointSizeF(tf.pointSizeF() + 3);
    title->setFont(tf);
    header->addWidget(title);

    header->addStretch();
    m_statusText = new QLabel;
    header->addWidget(m_statusText);
    outer->addLayout(header);

    outer->addWidget(hLine());

    // --- Service panel ---
    auto *svcBox = new QGroupBox(tr("Windows service"));
    auto *svc = new QVBoxLayout(svcBox);
    m_serviceLabel = new QLabel;
    svc->addWidget(m_serviceLabel);

    auto *svcBtns = new QHBoxLayout;
    m_btnInstall = new QPushButton(tr("Install"));
    m_btnUninstall = new QPushButton(tr("Uninstall"));
    m_btnStart = new QPushButton(tr("Start"));
    m_btnStop = new QPushButton(tr("Stop"));
    m_btnInstall->setIcon(style()->standardIcon(QStyle::SP_ArrowDown));
    m_btnUninstall->setIcon(style()->standardIcon(QStyle::SP_TrashIcon));
    m_btnStart->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
    m_btnStop->setIcon(style()->standardIcon(QStyle::SP_MediaStop));
    svcBtns->addWidget(m_btnInstall);
    svcBtns->addWidget(m_btnUninstall);
    svcBtns->addWidget(m_btnStart);
    svcBtns->addWidget(m_btnStop);
    svcBtns->addStretch();
    svc->addLayout(svcBtns);
    outer->addWidget(svcBox);

    // --- Action bar: adopt / create tunnel ---
    auto *actionBar = new QHBoxLayout;
    auto *btnAdopt = new QPushButton(tr("Adopt…"));
    auto *btnCreate = new QPushButton(tr("New tunnel…"));
    btnAdopt->setIcon(style()->standardIcon(QStyle::SP_ArrowDown));
    btnCreate->setIcon(IconFactory::plusIcon(Theme::Colors::connected()));
    connect(btnAdopt, &QPushButton::clicked, this, &MainWindow::openAdopt);
    connect(btnCreate, &QPushButton::clicked, this, &MainWindow::openCreate);
    actionBar->addWidget(btnAdopt);
    actionBar->addWidget(btnCreate);
    actionBar->addStretch();
    outer->addLayout(actionBar);

    auto runService = [this](bool (*action)(QString *)) {
        QString err;
        if (!action(&err)) {
            if (!err.isEmpty())
                statusBar()->showMessage(err, 5000);
            return;
        }
        // Elevated action is fire-and-forget; nudge a couple of refreshes.
        QTimer::singleShot(1200, m_state, &AppState::refreshServiceState);
        QTimer::singleShot(3000, m_state, &AppState::refreshServiceState);
    };
    connect(m_btnInstall, &QPushButton::clicked, this,
            [runService]() { runService(&ServiceController::install); });
    connect(m_btnUninstall, &QPushButton::clicked, this,
            [runService]() { runService(&ServiceController::uninstall); });
    connect(m_btnStart, &QPushButton::clicked, this,
            [runService]() { runService(&ServiceController::start); });
    connect(m_btnStop, &QPushButton::clicked, this,
            [runService]() { runService(&ServiceController::stop); });

    // --- Scrollable content (tunnels + clusters) ---
    auto *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    auto *scrollInner = new QWidget;
    auto *content = new QVBoxLayout(scrollInner);
    content->setContentsMargins(0, 0, 0, 0);
    content->setSpacing(Theme::Spacing::Sm);

    m_tunnelsHeader = sectionHeader(tr("ACTIVE TUNNELS"));
    content->addWidget(m_tunnelsHeader);
    m_emptyLabel = new QLabel(tr("No active tunnels."));
    m_emptyLabel->setStyleSheet(QStringLiteral("color: palette(mid);"));
    content->addWidget(m_emptyLabel);
    m_tunnelsLayout = new QVBoxLayout;
    m_tunnelsLayout->setSpacing(Theme::Spacing::Xs);
    content->addLayout(m_tunnelsLayout);

    m_clustersHeader = sectionHeader(tr("AVAILABLE CLUSTERS"));
    content->addWidget(m_clustersHeader);
    m_clustersLayout = new QVBoxLayout;
    m_clustersLayout->setSpacing(Theme::Spacing::Xs);
    content->addLayout(m_clustersLayout);

    content->addStretch();
    scroll->setWidget(scrollInner);
    outer->addWidget(scroll, 1);

    outer->addWidget(hLine());

    // --- Footer ---
    auto *footer = new QHBoxLayout;
    m_versionLabel = new QLabel;
    m_versionLabel->setStyleSheet(QStringLiteral("color: palette(mid);"));
    footer->addWidget(m_versionLabel);
    footer->addStretch();

    m_updateButton = new QPushButton;
    m_updateButton->setIcon(style()->standardIcon(QStyle::SP_ArrowDown));
    m_updateButton->setVisible(false);
    connect(m_updateButton, &QPushButton::clicked, this, [this]() {
        const auto rel = m_state->update();
        const QString url = !rel.assetUrl.isEmpty() ? rel.assetUrl : rel.htmlUrl;
        if (!url.isEmpty())
            QDesktopServices::openUrl(QUrl(url));
    });
    footer->addWidget(m_updateButton);

    auto *openConfig = new QPushButton(tr("Open config folder"));
    openConfig->setIcon(style()->standardIcon(QStyle::SP_DirOpenIcon));
    connect(openConfig, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl::fromLocalFile(ClusterDiscovery::configDir()));
    });
    footer->addWidget(openConfig);
    outer->addLayout(footer);

    setCentralWidget(central);
}

void MainWindow::refresh()
{
    // Header.
    const AppState::OverallState os = m_state->overallState();
    QColor dot;
    switch (os) {
    case AppState::OverallState::Connected:
        dot = Theme::Colors::connected();
        break;
    case AppState::OverallState::Partial:
        dot = Theme::Colors::partial();
        break;
    case AppState::OverallState::Disconnected:
        dot = Theme::Colors::disconnected();
        break;
    case AppState::OverallState::DaemonDown:
        dot = Theme::Colors::daemonDown();
        break;
    }
    m_statusDot->setPixmap(IconFactory::statusDot(dot, 12));
    m_statusText->setText(m_state->statusText());

    updateServicePanel();
    rebuildTunnels();
    rebuildClusters();

    // Footer.
    m_versionLabel->setText(QStringLiteral("v%1").arg(m_state->appVersion()));
    if (m_state->hasUpdate()) {
        m_updateButton->setText(tr("Update to %1").arg(m_state->update().version));
        m_updateButton->setVisible(true);
    } else {
        m_updateButton->setVisible(false);
    }
}

void MainWindow::updateServicePanel()
{
    using S = ServiceController::State;
    const S s = m_state->serviceState();
    m_serviceLabel->setText(tr("Status: %1").arg(ServiceController::stateLabel(s)));

    m_btnInstall->setEnabled(s == S::NotInstalled);
    m_btnUninstall->setEnabled(s == S::Stopped || s == S::Running);
    m_btnStart->setEnabled(s == S::Stopped);
    m_btnStop->setEnabled(s == S::Running);

    const bool supported = s != S::Unsupported;
    m_btnInstall->setVisible(supported);
    m_btnUninstall->setVisible(supported);
    m_btnStart->setVisible(supported);
    m_btnStop->setVisible(supported);
}

void MainWindow::rebuildTunnels()
{
    clearLayout(m_tunnelsLayout);

    const auto &tunnels = m_state->tunnels();
    m_tunnelsHeader->setText(tr("ACTIVE TUNNELS (%1)").arg(tunnels.size()));
    m_emptyLabel->setVisible(tunnels.isEmpty() && m_state->daemonReachable());

    for (const mlsh::TunnelStatus &t : tunnels) {
        auto *rowWidget = new TunnelRow(t, m_state->isClusterBusy(t.cluster));
        connect(rowWidget, &TunnelRow::disconnectRequested, m_state,
                &AppState::disconnectCluster);
        connect(rowWidget, &TunnelRow::copyIpRequested, this, &MainWindow::onCopyIp);
        connect(rowWidget, &TunnelRow::menuRequested, this,
                [this](const QString &c) { showClusterMenu(c, true); });
        m_tunnelsLayout->addWidget(rowWidget);
    }
}

void MainWindow::rebuildClusters()
{
    clearLayout(m_clustersLayout);

    const QStringList clusters = m_state->disconnectedClusters();
    m_clustersHeader->setVisible(!clusters.isEmpty());

    for (const QString &cluster : clusters) {
        auto *row = new QFrame;
        row->setFrameShape(QFrame::StyledPanel);
        auto *h = new QHBoxLayout(row);
        h->setContentsMargins(Theme::Spacing::Md, Theme::Spacing::Xs,
                              Theme::Spacing::Md, Theme::Spacing::Xs);
        h->addWidget(new QLabel(cluster), 1);

        const bool busy = m_state->isClusterBusy(cluster);
        auto *btn = new QPushButton(busy ? tr("Connecting…") : tr("Connect"));
        if (!busy)
            btn->setIcon(style()->standardIcon(QStyle::SP_ArrowForward));
        btn->setEnabled(!busy);
        connect(btn, &QPushButton::clicked, m_state,
                [this, cluster]() { m_state->connectCluster(cluster); });
        h->addWidget(btn);

        auto *menuBtn = new QPushButton(tr("⋯"));
        menuBtn->setFixedSize(28, 24);
        menuBtn->setToolTip(tr("More actions"));
        connect(menuBtn, &QPushButton::clicked, this,
                [this, cluster]() { showClusterMenu(cluster, false); });
        h->addWidget(menuBtn);

        m_clustersLayout->addWidget(row);
    }
}

void MainWindow::onCopyIp(const QString &ip)
{
    QApplication::clipboard()->setText(ip);
    statusBar()->showMessage(tr("Copied %1").arg(ip), 1500);
}

void MainWindow::showClusterMenu(const QString &cluster, bool active)
{
    QMenu menu(this);

    QAction *nodes = menu.addAction(tr("Nodes…"));
    nodes->setEnabled(active); // needs a connected tunnel to reach the control plane
    connect(nodes, &QAction::triggered, this, [this, cluster]() { openNodes(cluster); });

    if (m_state->isClusterAdmin(cluster)) {
        QAction *invite = menu.addAction(tr("Invite…"));
        connect(invite, &QAction::triggered, this, [this, cluster]() { openInvite(cluster); });
    }

    menu.addSeparator();
    QAction *remove = menu.addAction(tr("Remove…"));
    connect(remove, &QAction::triggered, this, [this, cluster]() { removeCluster(cluster); });

    menu.exec(QCursor::pos());
}

void MainWindow::openAdopt()
{
    AdoptDialog dlg(m_state, this);
    dlg.exec();
}

void MainWindow::openCreate()
{
    CreateTunnelDialog dlg(m_state, this);
    dlg.exec();
}

void MainWindow::openInvite(const QString &cluster)
{
    InviteDialog dlg(m_state, cluster, this);
    dlg.exec();
}

void MainWindow::openNodes(const QString &cluster)
{
    NodesDialog dlg(m_state, cluster, this);
    dlg.exec();
}

void MainWindow::removeCluster(const QString &cluster)
{
    if (QMessageBox::question(
            this, tr("Remove tunnel"),
            tr("Remove '%1'? This disconnects it and deletes its local config.\n"
               "(The node stays registered in the cluster unless revoked by an admin.)")
                .arg(cluster))
        != QMessageBox::Yes)
        return;
    m_state->removeTunnel(cluster);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    // Keep running in the tray instead of quitting.
    hide();
    event->ignore();
}
