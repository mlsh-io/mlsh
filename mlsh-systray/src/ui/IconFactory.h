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

/// A filled dot QIcon (for table cells, etc.).
QIcon dotIcon(const QColor &color, int size = 12);

/// A "+" glyph icon in the given color (for "add/new" buttons).
QIcon plusIcon(const QColor &color);

} // namespace IconFactory
