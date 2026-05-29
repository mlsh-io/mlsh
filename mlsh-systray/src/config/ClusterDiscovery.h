#pragma once

#include <QString>
#include <QStringList>

/// Reads the user's mlsh config under ~/.config/mlsh (same layout on every
/// platform, including Windows — see mlsh-cli/src/config.rs).
namespace ClusterDiscovery {

/// `~/.config/mlsh`.
QString configDir();

/// Cluster names from `~/.config/mlsh/clusters/*.toml`, sorted.
QStringList availableClusters();

/// Read the three files a `connect` request needs: the cluster TOML and the
/// node identity cert/key. Returns false and sets `error` on failure.
bool readConnectMaterial(const QString &cluster,
                         QString &configToml,
                         QString &certPem,
                         QString &keyPem,
                         QString &error);

} // namespace ClusterDiscovery
