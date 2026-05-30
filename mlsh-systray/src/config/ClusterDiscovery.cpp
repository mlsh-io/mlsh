#include "config/ClusterDiscovery.h"

#include <QDir>
#include <QFile>

// toml++ is header-only and uses exceptions by default; keep them on so a
// malformed file throws toml::parse_error (caught below) rather than UB.
#include <tomlplusplus/toml.hpp>

#include <optional>
#include <string>

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

/// Parse a cluster's TOML into a toml++ table. Reads via QFile (UTF-8) rather
/// than toml::parse_file() so non-ASCII paths (e.g. a username) work on Windows.
/// Returns nullopt if the file is missing or malformed.
static std::optional<toml::table> parseClusterToml(const QString &cluster)
{
    QString content, err;
    if (!readFile(clusterTomlPath(cluster), content, err))
        return std::nullopt;
    try {
        return toml::parse(content.toStdString());
    } catch (const toml::parse_error &) {
        return std::nullopt;
    }
}

QStringList clusterRoles(const QString &cluster)
{
    const auto tbl = parseClusterToml(cluster);
    if (!tbl)
        return {};

    QStringList roles;
    if (const toml::array *arr = (*tbl)["node_auth"]["roles"].as_array()) {
        for (const toml::node &el : *arr) {
            if (const auto s = el.value<std::string>())
                roles << QString::fromStdString(*s);
        }
    }
    return roles;
}

bool isClusterAdmin(const QString &cluster)
{
    return clusterRoles(cluster).contains(QStringLiteral("admin"));
}

QString clusterNodeUuid(const QString &cluster)
{
    const auto tbl = parseClusterToml(cluster);
    if (!tbl)
        return {};

    // New files store `node_uuid`; older ones used `node_id`.
    auto v = (*tbl)["node_auth"]["node_uuid"].value<std::string>();
    if (!v)
        v = (*tbl)["node_auth"]["node_id"].value<std::string>();
    return v ? QString::fromStdString(*v) : QString();
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
