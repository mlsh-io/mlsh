#pragma once

#include "model/TunnelStatus.h"

#include <QFrame>

/// One row in the "Active tunnels" list (parity with TunnelRowView.swift):
/// status dot, cluster name, overlay IP (click to copy), transport badge,
/// uptime, ↑/↓ traffic, last error, and a disconnect button.
class TunnelRow : public QFrame
{
    Q_OBJECT
public:
    TunnelRow(const mlsh::TunnelStatus &tunnel, bool busy, QWidget *parent = nullptr);

signals:
    void disconnectRequested(const QString &cluster);
    void copyIpRequested(const QString &ip);
};
