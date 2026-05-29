#include "ipc/Protocol.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace mlsh {

TunnelState tunnelStateFromString(const QString &s)
{
    if (s == QLatin1String("disconnected"))
        return TunnelState::Disconnected;
    if (s == QLatin1String("connecting"))
        return TunnelState::Connecting;
    if (s == QLatin1String("connected"))
        return TunnelState::Connected;
    if (s == QLatin1String("reconnecting"))
        return TunnelState::Reconnecting;
    return TunnelState::Unknown;
}

QString tunnelStateToString(TunnelState state)
{
    switch (state) {
    case TunnelState::Disconnected:
        return QStringLiteral("disconnected");
    case TunnelState::Connecting:
        return QStringLiteral("connecting");
    case TunnelState::Connected:
        return QStringLiteral("connected");
    case TunnelState::Reconnecting:
        return QStringLiteral("reconnecting");
    case TunnelState::Unknown:
        break;
    }
    return QStringLiteral("unknown");
}

static QByteArray encode(const QJsonObject &obj)
{
    return QJsonDocument(obj).toJson(QJsonDocument::Compact);
}

QByteArray buildStatusRequest()
{
    QJsonObject obj;
    obj[QStringLiteral("type")] = QStringLiteral("status");
    return encode(obj);
}

QByteArray buildConnectRequest(const QString &cluster,
                               const QString &configToml,
                               const QString &certPem,
                               const QString &keyPem)
{
    QJsonObject obj;
    obj[QStringLiteral("type")] = QStringLiteral("connect");
    obj[QStringLiteral("cluster")] = cluster;
    obj[QStringLiteral("config_toml")] = configToml;
    obj[QStringLiteral("cert_pem")] = certPem;
    obj[QStringLiteral("key_pem")] = keyPem;
    return encode(obj);
}

QByteArray buildDisconnectRequest(const QString &cluster)
{
    QJsonObject obj;
    obj[QStringLiteral("type")] = QStringLiteral("disconnect");
    obj[QStringLiteral("cluster")] = cluster;
    return encode(obj);
}

static TunnelStatus parseTunnel(const QJsonObject &o)
{
    TunnelStatus t;
    t.cluster = o.value(QStringLiteral("cluster")).toString();
    t.state = tunnelStateFromString(o.value(QStringLiteral("state")).toString());
    t.transport = o.value(QStringLiteral("transport")).toString();
    t.overlayIp = o.value(QStringLiteral("overlay_ip")).toString();
    if (o.contains(QStringLiteral("uptime_secs"))
        && !o.value(QStringLiteral("uptime_secs")).isNull()) {
        t.uptimeSecs = o.value(QStringLiteral("uptime_secs")).toVariant().toULongLong();
    }
    t.bytesTx = o.value(QStringLiteral("bytes_tx")).toVariant().toULongLong();
    t.bytesRx = o.value(QStringLiteral("bytes_rx")).toVariant().toULongLong();
    t.lastError = o.value(QStringLiteral("last_error")).toString();
    return t;
}

DaemonResponse parseResponse(const QByteArray &json)
{
    DaemonResponse resp;

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return resp; // parsed == false

    resp.parsed = true;
    const QJsonObject obj = doc.object();
    const QString type = obj.value(QStringLiteral("type")).toString();

    if (type == QLatin1String("ok")) {
        resp.type = ResponseType::Ok;
        resp.message = obj.value(QStringLiteral("message")).toString();
    } else if (type == QLatin1String("error")) {
        resp.type = ResponseType::Error;
        resp.errorCode = obj.value(QStringLiteral("code")).toString();
        resp.message = obj.value(QStringLiteral("message")).toString();
    } else if (type == QLatin1String("status")) {
        resp.type = ResponseType::Status;
        const QJsonArray arr = obj.value(QStringLiteral("tunnels")).toArray();
        for (const QJsonValue &v : arr)
            resp.tunnels.append(parseTunnel(v.toObject()));
    } else {
        resp.type = ResponseType::Unknown;
    }

    return resp;
}

} // namespace mlsh
