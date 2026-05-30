#include "ui/TunnelRow.h"

#include "ui/Formatting.h"
#include "ui/IconFactory.h"
#include "ui/Theme.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

QColor dotColor(mlsh::TunnelState state)
{
    switch (state) {
    case mlsh::TunnelState::Connected:
        return Theme::Colors::connected();
    case mlsh::TunnelState::Connecting:
    case mlsh::TunnelState::Reconnecting:
        return Theme::Colors::partial();
    default:
        return Theme::Colors::disconnected();
    }
}

QLabel *caption(const QString &text)
{
    auto *l = new QLabel(text);
    QFont f = l->font();
    f.setPointSizeF(f.pointSizeF() - 1);
    l->setFont(f);
    l->setStyleSheet(QStringLiteral("color: palette(mid);"));
    return l;
}

} // namespace

TunnelRow::TunnelRow(const mlsh::TunnelStatus &tunnel, bool busy, QWidget *parent)
    : QFrame(parent)
{
    setFrameShape(QFrame::StyledPanel);
    setObjectName(QStringLiteral("tunnelRow"));

    auto *row = new QHBoxLayout(this);
    row->setContentsMargins(Theme::Spacing::Md, Theme::Spacing::Sm,
                            Theme::Spacing::Md, Theme::Spacing::Sm);
    row->setSpacing(Theme::Spacing::Md);

    // Status dot.
    auto *dot = new QLabel;
    dot->setPixmap(IconFactory::statusDot(dotColor(tunnel.state), 10));
    dot->setFixedSize(10, 10);
    row->addWidget(dot, 0, Qt::AlignTop);

    // Middle column.
    auto *col = new QVBoxLayout;
    col->setSpacing(Theme::Spacing::Xxs);

    auto *name = new QLabel(tunnel.cluster);
    QFont nf = name->font();
    nf.setBold(true);
    name->setFont(nf);
    col->addWidget(name);

    // Metadata: IP · transport · uptime.
    auto *meta = new QHBoxLayout;
    meta->setSpacing(Theme::Spacing::Sm);
    if (!tunnel.overlayIp.isEmpty()) {
        auto *ipBtn = new QToolButton;
        ipBtn->setText(tunnel.overlayIp);
        ipBtn->setAutoRaise(true);
        ipBtn->setCursor(Qt::PointingHandCursor);
        ipBtn->setToolTip(tr("Click to copy IP"));
        const QString ip = tunnel.overlayIp;
        connect(ipBtn, &QToolButton::clicked, this,
                [this, ip]() { emit copyIpRequested(ip); });
        meta->addWidget(ipBtn);
    }
    if (!tunnel.transport.isEmpty()) {
        auto *badge = new QLabel(tunnel.transport);
        badge->setStyleSheet(QStringLiteral(
            "background: palette(midlight); border-radius: 6px; padding: 1px 6px;"));
        meta->addWidget(badge);
    }
    if (tunnel.uptimeSecs.has_value())
        meta->addWidget(caption(formatUptime(tunnel.uptimeSecs.value())));
    meta->addStretch();
    col->addLayout(meta);

    // Traffic.
    if (tunnel.bytesTx > 0 || tunnel.bytesRx > 0) {
        auto *traffic = new QLabel(
            QStringLiteral("↑ %1   ↓ %2")
                .arg(formatBytes(tunnel.bytesTx), formatBytes(tunnel.bytesRx)));
        QFont tf = traffic->font();
        tf.setPointSizeF(tf.pointSizeF() - 1);
        traffic->setFont(tf);
        col->addWidget(traffic);
    }

    // Error.
    if (!tunnel.lastError.isEmpty()) {
        auto *err = new QLabel(QStringLiteral("⚠ %1").arg(tunnel.lastError));
        err->setWordWrap(true);
        err->setStyleSheet(
            QStringLiteral("color: %1;").arg(Theme::Colors::daemonDown().name()));
        col->addWidget(err);
    }

    row->addLayout(col, 1);

    const QString cluster = tunnel.cluster;

    // "⋯" menu button (invite / nodes / remove — built by MainWindow).
    auto *menuBtn = new QPushButton(tr("⋯"));
    menuBtn->setToolTip(tr("More actions"));
    menuBtn->setFixedSize(28, 24);
    connect(menuBtn, &QPushButton::clicked, this,
            [this, cluster]() { emit menuRequested(cluster); });
    row->addWidget(menuBtn, 0, Qt::AlignTop);

    // Disconnect button.
    auto *btn = new QPushButton(busy ? tr("…") : tr("✕"));
    btn->setToolTip(tr("Disconnect"));
    btn->setFixedSize(28, 24);
    btn->setEnabled(!busy);
    connect(btn, &QPushButton::clicked, this,
            [this, cluster]() { emit disconnectRequested(cluster); });
    row->addWidget(btn, 0, Qt::AlignTop);
}
