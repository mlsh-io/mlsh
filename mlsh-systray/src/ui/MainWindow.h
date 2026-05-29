#pragma once

#include <QMainWindow>

class AppState;
class QLabel;
class QPushButton;
class QVBoxLayout;
class QCloseEvent;

/// Resizable main window: status header, Windows-service panel, active tunnels,
/// available clusters, and a footer with version / update / config-folder.
class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(AppState *state, QWidget *parent = nullptr);

    void refresh();

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void buildUi();
    void rebuildTunnels();
    void rebuildClusters();
    void updateServicePanel();
    void onCopyIp(const QString &ip);

    AppState *m_state = nullptr;

    QLabel *m_statusDot = nullptr;
    QLabel *m_statusText = nullptr;

    QLabel *m_serviceLabel = nullptr;
    QPushButton *m_btnInstall = nullptr;
    QPushButton *m_btnUninstall = nullptr;
    QPushButton *m_btnStart = nullptr;
    QPushButton *m_btnStop = nullptr;

    QLabel *m_tunnelsHeader = nullptr;
    QVBoxLayout *m_tunnelsLayout = nullptr;
    QLabel *m_emptyLabel = nullptr;

    QLabel *m_clustersHeader = nullptr;
    QVBoxLayout *m_clustersLayout = nullptr;

    QLabel *m_versionLabel = nullptr;
    QPushButton *m_updateButton = nullptr;
};
