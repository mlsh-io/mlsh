#pragma once

#include <QString>

/// A cluster node as returned by `mlsh --json nodes <cluster>`
/// (data element fields: uuid, display_name, role, status, online, overlay_ip).
struct NodeInfo {
    QString uuid;
    QString displayName;
    QString role;      // "admin" | "node"
    QString status;    // "active" | "revoked" | ...
    QString overlayIp; // may be "-" / empty
    bool online = false;
};
