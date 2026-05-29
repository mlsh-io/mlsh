#pragma once

#include <QString>
#include <optional>

namespace mlsh {

/// Mirrors the daemon's `TunnelState` enum (protocol.rs).
enum class TunnelState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Unknown,
};

TunnelState tunnelStateFromString(const QString &s);
QString tunnelStateToString(TunnelState state);

/// Mirrors the daemon's `TunnelStatus` DTO (protocol.rs).
struct TunnelStatus {
    QString cluster;
    TunnelState state = TunnelState::Unknown;
    QString transport;                 // empty if absent
    QString overlayIp;                 // empty if absent
    std::optional<quint64> uptimeSecs; // absent until connected
    quint64 bytesTx = 0;
    quint64 bytesRx = 0;
    QString lastError;                 // empty if none
};

} // namespace mlsh
