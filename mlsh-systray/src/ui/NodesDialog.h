#pragma once

#include "model/NodeInfo.h"

#include <QDialog>
#include <QList>
#include <QString>

class AppState;
class QTableWidget;
class QPushButton;
class QLabel;

/// Lists the nodes of a cluster (`mlsh --json nodes`). If the local node is an
/// admin, allows rename / promote-demote / revoke (`mlsh --json rename|promote|
/// revoke`).
class NodesDialog : public QDialog
{
    Q_OBJECT
public:
    NodesDialog(AppState *state, const QString &cluster, QWidget *parent = nullptr);

private:
    void refresh();
    void populate(const QList<NodeInfo> &nodes);
    NodeInfo selectedNode() const;
    void updateButtons();

    void doRename();
    void doToggleRole();
    void doRevoke();

    AppState *m_state = nullptr;
    QString m_cluster;
    QString m_selfUuid;
    bool m_admin = false;

    QTableWidget *m_table = nullptr;
    QPushButton *m_rename = nullptr;
    QPushButton *m_role = nullptr;
    QPushButton *m_revoke = nullptr;
    QPushButton *m_refresh = nullptr;
    QLabel *m_status = nullptr;
    QList<NodeInfo> m_nodes;
};
