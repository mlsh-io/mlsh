+++
title = "First Connection"
description = "Bootstrap a cluster, invite a second node, and open your first tunnel."
weight = 2
+++

This walks you through the four-command lifecycle: **setup** the first admin node, **invite** a second machine, **adopt** the invite on that machine, and **connect**.

## Prerequisites

- MLSH installed on two machines ([installation](@/getting-started/installation.md)).
- A running signal server reachable from the public internet on UDP/443 and TCP/443 ([deployment](@/signal-server/deployment.md)).
- A setup token generated with `mlsh-signal cluster create <cluster-name>` ([see deployment](@/signal-server/deployment.md#create-a-cluster-and-setup-token)). It looks like `XXXX-XXXX-XXXX@<cluster-id>@<fingerprint>` and expires 15 minutes after creation by default.

## 1. Setup: bootstrap the first node

On your first machine, run:

```sh
mlsh setup homelab \
  --signal-host signal.example.com \
  --token XXXX-XXXX-XXXX@abc123def456
```

This connects to the signal server, verifies its TLS certificate by fingerprint, registers the node as an admin, and receives an overlay IP. The cluster configuration is written to `~/.config/mlsh/clusters/homelab.toml`. An Ed25519 identity keypair is generated in `~/.config/mlsh/identity/` if one does not already exist.

## 2. Invite: vouch for a new node

Still on the admin machine:

```sh
mlsh invite homelab --ttl 3600 --role node
```

This prints a signed invite URL (`https://signal.example.com/invite?token=XXXX-XXXX`) and a QR code. The invite is signed with your node's Ed25519 private key and carries the cluster ID, your node ID as sponsor, the target role, an expiration timestamp, and the signal server's fingerprint. Default TTL is one hour.

## 3. Adopt: join the cluster on the new machine

```sh
mlsh adopt "https://signal.example.com/invite?token=XXXX-XXXX" --name nas
```

The CLI decodes the invite and presents it to the signal server. If the sponsor's signature checks out and the invite hasn't expired, the new node is registered. It receives an overlay IP and a node token for future reconnections.

## 4. Connect: bring up the overlay tunnel

On both machines:

```sh
mlsh connect homelab
```

The daemon authenticates to the signal server, receives the peer list, gathers local network candidates, and establishes direct QUIC tunnels to every peer.

## Verify

```sh
mlsh status
```

You should see the cluster as `connected`, the overlay IP of your node, and uptime + traffic counters for each peer.

From either machine, the other is reachable by name:

```sh
ssh nas.homelab
```

## Next

- Deep-dive into [concepts](@/getting-started/concepts.md): sponsorship, overlay network, DNS.
- See the full [CLI reference](@/cli/reference.md).
