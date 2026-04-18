+++
title = "Command Reference"
description = "Every mlsh subcommand with its flags and a concrete example."
weight = 1
+++

Run `mlsh help <command>` for the canonical in-binary help.

## `mlsh setup`

Bootstraps a node in a cluster. In self-hosted mode, supply both `--signal-host` and the `--token` obtained from `mlsh-signal cluster create` ([see deployment](@/signal-server/deployment.md#create-a-cluster-and-setup-token)).

```sh
mlsh setup <cluster> \
  --signal-host <host> \
  --token <CODE>@<UUID>@<FINGERPRINT>
```

| Flag | Description |
|---|---|
| `<cluster>` | Cluster name (`homelab`, `prod`, …). |
| `--signal-host <host>` | Hostname of the signal server (self-hosted). |
| `--token <token>` | Setup token in the form `<CODE>@<UUID>@<FINGERPRINT>`. |
| `--name <name>` | Override the node name. Defaults to the machine hostname. |

Writes `~/.config/mlsh/clusters/<cluster>.toml`.

## `mlsh adopt`

Enrolls this machine in a cluster using an invite URL.

```sh
mlsh adopt "https://signal.example.com/invite?token=XXXX-XXXX" --name nas
```

| Flag | Description |
|---|---|
| `<url>` | The signed invite URL. |
| `--name <name>` | Node name for this machine. Defaults to the system username. |

## `mlsh invite`

Generates a signed invite URL for another machine to join this cluster. Admin-only.

```sh
mlsh invite <cluster> --ttl 3600 --role node
```

| Flag | Description |
|---|---|
| `<cluster>` | Cluster to invite into. |
| `--ttl <seconds>` | Invite lifetime. Default `3600`. |
| `--role {admin\|node}` | Role granted on adoption. Default `node`. |

Prints a `https://…/invite?token=…` URL and a terminal QR code.

## `mlsh connect`

Activates the overlay tunnel for a cluster.

```sh
mlsh connect <name>
```

| Flag | Description |
|---|---|
| `<name>` | Peer name, or `node.cluster` form (e.g. `homelab` or `nas.homelab`). |
| `--foreground` | Run the tunnel in the foreground, bypassing the daemon. Useful for debugging. |

## `mlsh disconnect`

Tears down the overlay tunnel for a peer.

```sh
mlsh disconnect <name>
```

## `mlsh status`

Prints the state of all active clusters: overlay IP, uptime, peers, and traffic counters.

```sh
mlsh status
```

## `mlsh nodes`

Lists all nodes in a cluster with their online/offline status.

```sh
mlsh nodes <cluster>
```

## `mlsh promote`

Changes a node's role in a cluster. Admin-only.

```sh
mlsh promote <cluster> <node> --role admin
```

| Flag | Description |
|---|---|
| `<cluster>` | Cluster name. |
| `<node>` | Node ID to promote or demote. |
| `--role {admin\|node}` | New role. |

## `mlsh revoke`

Removes a node from a cluster. Admin-only. The revoked node can no longer authenticate to the signal server.

```sh
mlsh revoke <cluster> <node>
```

## `mlsh rename`

Renames a node's display name in a cluster. Admin-only.

```sh
mlsh rename <cluster> <node> <new-name>
```

## `mlsh identity-export`

Exports the node's identity (private Ed25519 key) to stdout for backup.

```sh
mlsh identity-export > mlsh-identity.pem
```

## `mlsh identity-import`

Imports a node identity from a PEM file, or from stdin if no file is given.

```sh
mlsh identity-import mlsh-identity.pem
```

## `mlsh expose`

Exposes a local service to the public internet over HTTPS by publishing a domain that routes through the signal server's TLS ingress to this node.

```sh
mlsh expose <cluster> <target> \
  --domain myapp.<cluster>.example.com \
  --email you@example.com
```

| Flag | Description |
|---|---|
| `<cluster>` | Cluster name. |
| `<target>` | Upstream service URL, e.g. `http://localhost:3000`. |
| `--domain <fqdn>` | Public domain. Must be `*.<cluster>.example.com` (a domain you control, delegated to the signal server). |
| `--email <addr>` | Contact email for the Let's Encrypt ACME account. |
| `--acme-staging` | Use Let's Encrypt's staging directory (recommended while testing; production has hard rate limits). |

## `mlsh unexpose`

Removes a previously exposed service.

```sh
mlsh unexpose <cluster> <domain>
```

## `mlsh exposed`

Lists services currently exposed in a cluster.

```sh
mlsh exposed <cluster>
```

## `mlsh tunnel`

Manages the overlay tunnel daemon (`mlshtund`) as a system service.

- **macOS**: LaunchDaemon at `/Library/LaunchDaemons/io.mlsh.tund.plist`.
- **Linux**: systemd unit at `/etc/systemd/system/mlshtund.service`.

```sh
mlsh tunnel install --auto-connect homelab,prod
mlsh tunnel uninstall
mlsh tunnel status
```

| Subcommand | Description |
|---|---|
| `install` | Install `mlshtund` as a system daemon. `--auto-connect <list>` auto-connects the listed clusters on daemon start. |
| `uninstall` | Uninstall the daemon. |
| `status` | Show daemon installation status. |

See [config file](@/cli/config-file.md) for the on-disk format stored in `~/.config/mlsh/`.
