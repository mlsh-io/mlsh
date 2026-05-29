#include "config/ClusterDiscovery.h"

#include <QDir>
#include <QFile>

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

} // namespace ClusterDiscovery
