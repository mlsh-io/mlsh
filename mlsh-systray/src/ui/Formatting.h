#pragma once

#include <QString>

/// Byte/uptime formatters (parity with the macOS ByteFormatting.swift).
QString formatBytes(quint64 bytes);
QString formatUptime(quint64 seconds);
