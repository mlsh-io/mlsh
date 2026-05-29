#include "App.h"

#include "model/AppState.h"
#include "ui/MainWindow.h"
#include "ui/TrayIcon.h"

#include <QApplication>

App::App(QObject *parent)
    : QObject(parent)
    , m_state(new AppState(this))
{
    m_window = new MainWindow(m_state);
    m_tray = new TrayIcon(m_state, this);

    connect(m_tray, &TrayIcon::showWindowRequested, this, &App::showWindow);
    connect(m_tray, &TrayIcon::quitRequested, qApp, &QApplication::quit);

    m_tray->show();
    m_state->start();
}

App::~App()
{
    delete m_window; // not parented to a QObject (it's a top-level widget)
}

void App::showWindow()
{
    m_window->show();
    m_window->raise();
    m_window->activateWindow();
}
