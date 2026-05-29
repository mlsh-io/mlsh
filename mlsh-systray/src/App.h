#pragma once

#include <QObject>

class AppState;
class MainWindow;
class TrayIcon;

/// Root controller: owns the state model, the main window and the tray icon,
/// and wires them together. The app lives in the tray; the window is shown on
/// demand.
class App : public QObject
{
    Q_OBJECT
public:
    explicit App(QObject *parent = nullptr);
    ~App() override;

public slots:
    void showWindow();

private:

    AppState *m_state = nullptr;
    MainWindow *m_window = nullptr;
    TrayIcon *m_tray = nullptr;
};
