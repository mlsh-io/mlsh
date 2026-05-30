#pragma once

#include <QDialog>
#include <QString>

class AppState;
class QComboBox;
class QSpinBox;
class QLineEdit;
class QLabel;
class QPushButton;

/// Generate a signed invite URL for a cluster (`mlsh --json invite`).
class InviteDialog : public QDialog
{
    Q_OBJECT
public:
    InviteDialog(AppState *state, const QString &cluster, QWidget *parent = nullptr);

private:
    void generate();

    AppState *m_state = nullptr;
    QString m_cluster;
    QComboBox *m_role = nullptr;
    QSpinBox *m_ttl = nullptr;
    QPushButton *m_generate = nullptr;
    QLineEdit *m_url = nullptr;
    QPushButton *m_copy = nullptr;
    QLabel *m_status = nullptr;
};
