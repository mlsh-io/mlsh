#pragma once

#include <QDialog>
#include <QString>

class AppState;
class CliRunner;
class QLineEdit;
class QPushButton;
class QPlainTextEdit;
class QLabel;

/// Create a new cluster. Two tabs:
///  - Managed: `mlsh setup <cluster>` (human mode, device-flow) streamed live —
///    shows the verification URL + code and waits for browser authorization.
///  - Self-hosted: `mlsh --json setup <cluster> --signal-host … --token …`.
class CreateTunnelDialog : public QDialog
{
    Q_OBJECT
public:
    explicit CreateTunnelDialog(AppState *state, QWidget *parent = nullptr);

protected:
    void reject() override;

private:
    QWidget *buildManagedTab();
    QWidget *buildSelfHostedTab();
    void startManaged();
    void onManagedLine(const QString &line);
    void onManagedFinished(int exitCode);
    void startSelfHosted();

    AppState *m_state = nullptr;
    CliRunner *m_runner = nullptr; // managed streaming process

    // Managed tab
    QLineEdit *m_mgCluster = nullptr;
    QLineEdit *m_mgName = nullptr;
    QPushButton *m_mgCreate = nullptr;
    QLabel *m_mgCode = nullptr;
    QPushButton *m_mgVisit = nullptr;
    QPlainTextEdit *m_mgLog = nullptr;
    QString m_visitUrl;

    // Self-hosted tab
    QLineEdit *m_shCluster = nullptr;
    QLineEdit *m_shHost = nullptr;
    QLineEdit *m_shToken = nullptr;
    QLineEdit *m_shName = nullptr;
    QPushButton *m_shCreate = nullptr;
    QLabel *m_shStatus = nullptr;
};
