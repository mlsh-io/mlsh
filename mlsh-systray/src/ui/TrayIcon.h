#pragma once

#include <QObject>

class AppState;
class QSystemTrayIcon;
class QMenu;

/// System-tray icon + context menu. The icon is tinted by connection state.
/// The menu offers quick connect/disconnect, service control, show-window and
/// quit. It is rebuilt whenever AppState changes.
class TrayIcon : public QObject
{
    Q_OBJECT
public:
    explicit TrayIcon(AppState *state, QObject *parent = nullptr);

    void show();

signals:
    void showWindowRequested();
    void quitRequested();

private:
    void refresh();
    void rebuildMenu();

    AppState *m_state = nullptr;
    QSystemTrayIcon *m_tray = nullptr;
    QMenu *m_menu = nullptr;
};
