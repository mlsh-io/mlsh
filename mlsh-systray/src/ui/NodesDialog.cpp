#include "ui/NodesDialog.h"

#include "config/ClusterDiscovery.h"
#include "model/AppState.h"

#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

NodesDialog::NodesDialog(AppState *state, const QString &cluster, QWidget *parent)
    : QDialog(parent)
    , m_state(state)
    , m_cluster(cluster)
{
    setWindowTitle(tr("Nodes — %1").arg(cluster));
    setModal(true);
    resize(640, 360);

    m_selfUuid = ClusterDiscovery::clusterNodeUuid(cluster);
    m_admin = m_state->isClusterAdmin(cluster);

    auto *outer = new QVBoxLayout(this);

    m_table = new QTableWidget(0, 5);
    m_table->setHorizontalHeaderLabels(
        {tr("Name"), tr("Role"), tr("Status"), tr("Overlay IP"), tr("Online")});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->verticalHeader()->setVisible(false);
    outer->addWidget(m_table, 1);

    auto *actions = new QHBoxLayout;
    if (m_admin) {
        m_rename = new QPushButton(tr("Rename…"));
        m_role = new QPushButton(tr("Promote/Demote"));
        m_revoke = new QPushButton(tr("Revoke…"));
        actions->addWidget(m_rename);
        actions->addWidget(m_role);
        actions->addWidget(m_revoke);
        connect(m_rename, &QPushButton::clicked, this, &NodesDialog::doRename);
        connect(m_role, &QPushButton::clicked, this, &NodesDialog::doToggleRole);
        connect(m_revoke, &QPushButton::clicked, this, &NodesDialog::doRevoke);
    } else {
        auto *note = new QLabel(tr("You are not an admin of this cluster (read-only)."));
        note->setStyleSheet(QStringLiteral("color: palette(mid);"));
        actions->addWidget(note);
    }
    actions->addStretch();
    m_refresh = new QPushButton(tr("Refresh"));
    actions->addWidget(m_refresh);
    outer->addLayout(actions);

    m_status = new QLabel;
    m_status->setWordWrap(true);
    m_status->setStyleSheet(QStringLiteral("color: palette(mid);"));
    outer->addWidget(m_status);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    outer->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    connect(m_refresh, &QPushButton::clicked, this, &NodesDialog::refresh);
    connect(m_table, &QTableWidget::itemSelectionChanged, this, &NodesDialog::updateButtons);

    refresh();
}

void NodesDialog::refresh()
{
    m_status->setText(tr("Loading…"));
    m_refresh->setEnabled(false);
    m_state->listNodes(m_cluster, [this](const CliRunner::Result &r) {
        m_refresh->setEnabled(true);
        if (!r.ok) {
            m_status->setText(r.error.isEmpty() ? tr("Failed to list nodes.") : r.error);
            return;
        }
        QList<NodeInfo> nodes;
        // data = { "nodes": [ {id, display_name, role, status, online, overlay_ip} ],
        //          "total", "online", "offline" }
        const QJsonArray arr = r.data.toObject().value(QStringLiteral("nodes")).toArray();
        for (const QJsonValue &v : arr) {
            const QJsonObject o = v.toObject();
            NodeInfo n;
            n.uuid = o.value(QStringLiteral("id")).toString();
            n.displayName = o.value(QStringLiteral("display_name")).toString();
            n.role = o.value(QStringLiteral("role")).toString();
            n.status = o.value(QStringLiteral("status")).toString();
            n.overlayIp = o.value(QStringLiteral("overlay_ip")).toString();
            n.online = o.value(QStringLiteral("online")).toBool();
            nodes << n;
        }
        populate(nodes);
        m_status->setText(tr("%1 node(s).").arg(nodes.size()));
    });
}

void NodesDialog::populate(const QList<NodeInfo> &nodes)
{
    m_nodes = nodes;
    m_table->setRowCount(nodes.size());
    for (int i = 0; i < nodes.size(); ++i) {
        const NodeInfo &n = nodes.at(i);
        auto set = [this, i](int col, const QString &text) {
            m_table->setItem(i, col, new QTableWidgetItem(text));
        };
        QString name = n.displayName.isEmpty() ? n.uuid : n.displayName;
        if (n.uuid == m_selfUuid)
            name += tr(" (this node)");
        set(0, name);
        set(1, n.role);
        set(2, n.status);
        set(3, n.overlayIp);
        set(4, n.online ? tr("●") : tr("○"));
    }
    updateButtons();
}

NodeInfo NodesDialog::selectedNode() const
{
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_nodes.size())
        return {};
    return m_nodes.at(row);
}

void NodesDialog::updateButtons()
{
    if (!m_admin)
        return;
    const NodeInfo n = selectedNode();
    const bool has = !n.uuid.isEmpty();
    const bool isSelf = has && n.uuid == m_selfUuid;
    m_rename->setEnabled(has);
    m_role->setEnabled(has);
    m_revoke->setEnabled(has && !isSelf); // don't revoke yourself
    if (has)
        m_role->setText(n.role == QStringLiteral("admin") ? tr("Demote to node")
                                                          : tr("Promote to admin"));
    else
        m_role->setText(tr("Promote/Demote"));
}

void NodesDialog::doRename()
{
    const NodeInfo n = selectedNode();
    if (n.uuid.isEmpty())
        return;
    bool ok = false;
    const QString name = QInputDialog::getText(
        this, tr("Rename node"), tr("New display name:"), QLineEdit::Normal, n.displayName, &ok);
    if (!ok || name.trimmed().isEmpty())
        return;
    m_state->renameNode(m_cluster, n.uuid, name.trimmed(),
                        [this](const CliRunner::Result &r) {
                            if (r.ok)
                                refresh();
                        });
}

void NodesDialog::doToggleRole()
{
    const NodeInfo n = selectedNode();
    if (n.uuid.isEmpty())
        return;
    const QString newRole =
        n.role == QStringLiteral("admin") ? QStringLiteral("node") : QStringLiteral("admin");
    m_state->promoteNode(m_cluster, n.uuid, newRole, [this](const CliRunner::Result &r) {
        if (r.ok)
            refresh();
    });
}

void NodesDialog::doRevoke()
{
    const NodeInfo n = selectedNode();
    if (n.uuid.isEmpty())
        return;
    const QString name = n.displayName.isEmpty() ? n.uuid : n.displayName;
    if (QMessageBox::question(this, tr("Revoke node"),
                              tr("Revoke '%1' from %2? This removes its access.")
                                  .arg(name, m_cluster))
        != QMessageBox::Yes)
        return;
    m_state->revokeNode(m_cluster, n.uuid, [this](const CliRunner::Result &r) {
        if (r.ok)
            refresh();
    });
}
