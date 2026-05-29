#pragma once

#include "model/TunnelStatus.h"

#include <QByteArray>
#include <QList>
#include <QString>

/// Wire protocol for the mlshtund control endpoint.
///
/// JSON messages with a 4-byte big-endian length prefix (see
/// mlsh-cli/src/tund/control/protocol.rs). This module only deals with the
/// JSON bodies; framing lives in DaemonClient.
namespace mlsh {

/// Discriminant of a daemon response (`type` field).
enum class ResponseType {
    Ok,
    Error,
    Status,
    Unknown, // any other variant we don't render (node_list, expose_ok, ...)
};

struct DaemonResponse {
    ResponseType type = ResponseType::Unknown;
    QString message;                 // ok.message / error.message
    QString errorCode;               // error.code
    QList<TunnelStatus> tunnels;     // status.tunnels
    bool parsed = false;             // false if the bytes weren't valid JSON
};

// --- Request builders (return the JSON body, unframed) -----------------------

QByteArray buildStatusRequest();
QByteArray buildConnectRequest(const QString &cluster,
                               const QString &configToml,
                               const QString &certPem,
                               const QString &keyPem);
QByteArray buildDisconnectRequest(const QString &cluster);

// --- Response parsing --------------------------------------------------------

DaemonResponse parseResponse(const QByteArray &json);

} // namespace mlsh
