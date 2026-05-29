#include "App.h"
#include "ui/IconFactory.h"

#include <QApplication>
#include <QLocalServer>
#include <QLocalSocket>
#include <QMessageBox>
#include <QSystemTrayIcon>

namespace {
constexpr char kSingletonKey[] = "mlsh-systray-singleton";

/// Returns true if another instance is already running.
bool anotherInstanceRunning()
{
    QLocalSocket probe;
    probe.connectToServer(QString::fromLatin1(kSingletonKey));
    if (probe.waitForConnected(200)) {
        probe.disconnectFromServer();
        return true;
    }
    return false;
}
} // namespace

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("mlsh-systray"));
    QApplication::setApplicationDisplayName(QStringLiteral("MLSH"));
    QApplication::setOrganizationName(QStringLiteral("mlsh"));
    QApplication::setWindowIcon(IconFactory::appIcon());

    // Live in the tray: closing the window must not quit the app.
    QApplication::setQuitOnLastWindowClosed(false);

    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        QMessageBox::critical(nullptr, QStringLiteral("MLSH"),
                              QObject::tr("No system tray is available on this system."));
        return 1;
    }

    if (anotherInstanceRunning())
        return 0; // hand off to the existing instance

    // Hold the singleton server for the app's lifetime.
    QLocalServer::removeServer(QString::fromLatin1(kSingletonKey));
    QLocalServer singleton;
    singleton.listen(QString::fromLatin1(kSingletonKey));

    App controller;

    // A second launch connects to the singleton; surface the window for it.
    QObject::connect(&singleton, &QLocalServer::newConnection, &controller, [&]() {
        while (QLocalSocket *c = singleton.nextPendingConnection())
            c->deleteLater();
        controller.showWindow();
    });

    // Open the window on a normal launch. Login autostart passes --hidden so the
    // app starts quietly in the tray.
    const QStringList args = QCoreApplication::arguments();
    if (!args.contains(QStringLiteral("--hidden"))
        && !args.contains(QStringLiteral("--minimized"))) {
        controller.showWindow();
    }

    return app.exec();
}
