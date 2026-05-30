#include "config/ClusterDiscovery.h"

#include <QDir>
#include <QFile>
#include <QRegularExpression>

namespace ClusterDiscovery {

QString configDir()
{
    // Mirror mlsh-cli: dirs::home_dir().join(".config").join("mlsh").
    // QDir::homePath() resolves to %USERPROFILE% on Windows.
    return QDir(QDir::homePath()).filePath(QStringLiteral(".config/mlsh"));
}

QStringList availableClusters()
{
    QDir clustersDir(QDir(configDir()).filePath(QStringLiteral("clusters")));
    if (!clustersDir.exists())
        return {};

    const QStringList files = clustersDir.entryList(
        QStringList{QStringLiteral("*.toml")}, QDir::Files, QDir::Name);

    QStringList names;
    names.reserve(files.size());
    for (const QString &f : files) {
        QString base = f;
        base.chop(5); // ".toml"
        names << base;
    }
    return names;
}

static bool readFile(const QString &path, QString &out, QString &error)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        error = QStringLiteral("Cannot read %1: %2").arg(path, f.errorString());
        return false;
    }
    out = QString::fromUtf8(f.readAll());
    return true;
}

bool readConnectMaterial(const QString &cluster,
                         QString &configToml,
                         QString &certPem,
                         QString &keyPem,
                         QString &error)
{
    const QDir dir(configDir());
    const QString clusterFile =
        dir.filePath(QStringLiteral("clusters/%1.toml").arg(cluster));
    const QString certFile = dir.filePath(QStringLiteral("identity/cert.pem"));
    const QString keyFile = dir.filePath(QStringLiteral("identity/key.pem"));

    return readFile(clusterFile, configToml, error)
        && readFile(certFile, certPem, error)
        && readFile(keyFile, keyPem, error);
}

static QString clusterTomlPath(const QString &cluster)
{
    return QDir(configDir()).filePath(QStringLiteral("clusters/%1.toml").arg(cluster));
}

static QString readClusterToml(const QString &cluster)
{
    QString toml, err;
    if (!readFile(clusterTomlPath(cluster), toml, err))
        return {};
    return toml;
}

QStringList clusterRoles(const QString &cluster)
{
    const QString toml = readClusterToml(cluster);
    if (toml.isEmpty())
        return {};

    // roles = ["node", "admin", "control"]   (only present under [node_auth])
    static const QRegularExpression rolesRe(QStringLiteral("roles\\s*=\\s*\\[([^\\]]*)\\]"));
    const QRegularExpressionMatch m = rolesRe.match(toml);
    if (!m.hasMatch())
        return {};

    QStringList roles;
    static const QRegularExpression strRe(QStringLiteral("\"([^\"]+)\""));
    auto it = strRe.globalMatch(m.captured(1));
    while (it.hasNext())
        roles << it.next().captured(1);
    return roles;
}

bool isClusterAdmin(const QString &cluster)
{
    return clusterRoles(cluster).contains(QStringLiteral("admin"));
}

QString clusterNodeUuid(const QString &cluster)
{
    const QString toml = readClusterToml(cluster);
    static const QRegularExpression re(QStringLiteral("node_uuid\\s*=\\s*\"([^\"]+)\""));
    const QRegularExpressionMatch m = re.match(toml);
    return m.hasMatch() ? m.captured(1) : QString();
}

bool removeClusterConfig(const QString &cluster, QString &error)
{
    const QString path = clusterTomlPath(cluster);
    QFile f(path);
    if (!f.exists())
        return true; // already gone
    if (!f.remove()) {
        error = QStringLiteral("Cannot delete %1: %2").arg(path, f.errorString());
        return false;
    }
    return true;
}

} // namespace ClusterDiscovery
