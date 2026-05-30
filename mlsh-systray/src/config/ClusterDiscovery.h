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

/// Roles the local node holds in `cluster` (`[node_auth].roles` in the TOML),
/// e.g. {"node","admin","control"}. Empty if unreadable.
QStringList clusterRoles(const QString &cluster);

/// True if the local node is an admin of `cluster` (offline, from the TOML).
bool isClusterAdmin(const QString &cluster);

/// The local node's UUID for `cluster` (`[node_auth].node_uuid`), or empty.
QString clusterNodeUuid(const QString &cluster);

/// Delete the cluster's TOML config file. Returns false + sets `error` on failure.
bool removeClusterConfig(const QString &cluster, QString &error);

} // namespace ClusterDiscovery
