#pragma once

#include <QColor>

/// Design tokens (parity with the macOS Theme.swift).
namespace Theme {

namespace Spacing {
constexpr int Xxs = 2;
constexpr int Xs = 4;
constexpr int Sm = 8;
constexpr int Md = 12;
constexpr int Lg = 16;
constexpr int Xl = 20;
} // namespace Spacing

namespace Colors {
inline QColor connected() { return QColor(0x34, 0xC7, 0x59); }   // green
inline QColor partial() { return QColor(0xFF, 0x9F, 0x0A); }     // orange
inline QColor disconnected() { return QColor(0x8E, 0x8E, 0x93); } // gray
inline QColor daemonDown() { return QColor(0xFF, 0x3B, 0x30); }  // red
inline QColor txArrow() { return QColor(0x34, 0xC7, 0x59); }
inline QColor rxArrow() { return QColor(0x0A, 0x84, 0xFF); }
} // namespace Colors

} // namespace Theme
