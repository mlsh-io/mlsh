#pragma once

#include "model/AppState.h"

#include <QColor>
#include <QIcon>
#include <QPixmap>

/// Renders the MLSH hexagonal-cube logo at runtime with QPainter (no QtSvg, no
/// binary assets). The tray icon is tinted by connection state for at-a-glance
/// status; filled when connected, outline otherwise.
namespace IconFactory {

QIcon trayIcon(AppState::OverallState state);
QIcon appIcon();
QPixmap statusDot(const QColor &color, int size);

} // namespace IconFactory
