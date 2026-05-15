+++
title = "Concepts"
description = "Clusters, nodes, the signal server, sponsorship, and the overlay network."
weight = 3
+++

A small vocabulary covers most of MLSH.

## Cluster

A named group of nodes that share an overlay network. You pick the name when you run `mlsh setup`: `homelab`, `prod`, `personal`, anything. One signal server can host multiple clusters.

## Node

A single machine participating in a cluster. Each node has:

- An **Ed25519 identity**: generated locally, never leaves the machine.
- A **`node_uuid`** (UUID v4): the stable, machine-readable identifier. Used in the protocol and on disk.
- A **`display_name`**: e.g. `nas`, `laptop`, `gateway`. The human-facing label, mutable via `mlsh rename`. Combined with the cluster name it becomes a DNS name: `nas.homelab`.
- An **overlay IP**: allocated by the signal server from the cluster's subnet (default `100.64.0.0/10`).
- One or more **roles**: `node` (regular member), `admin` (can invite/manage nodes), `control` (hosts the admin REST API and UI — exactly one node per cluster).

## Signal server

A single lightweight Rust binary (shipped as a container). It handles:

- Node registration and peer discovery.
- Invite verification.
- Relay fallback when direct connectivity fails.

It is **not** on the data path for healthy connections. Peers punch through NAT and talk directly once discovery is done.

## Control plane

The cluster's authoritative store of users, nodes, display names, and admin actions lives on a single node — the one with the `control` role. It exposes a REST API and serves the [admin UI](@/admin-ui/_index.md). Move it with `mlsh control {promote,demote,migrate}`.

In **self-hosted** mode the control plane manages its own human identities (passwords, TOTP, WebAuthn). In **managed** mode, identities come from an external provider via OAuth device flow: `mlsh setup` opens your browser to complete sign-in.

## Sponsorship

MLSH has no shared secret for ongoing membership. The cluster secret is used **once** to bootstrap the first admin. After that, new nodes join through **sponsorship**: an existing admin signs an invite, the new node presents it, and the signal server verifies the signature against the sponsor's public key.

This creates a verifiable trust chain: every node was either the original admin or was explicitly vouched for by an existing one. See [trust model](@/security/trust-model.md) for details.

## Overlay network

When a node connects, the daemon creates a TUN device named `mlsh0` with the node's overlay IP. Packets written to `mlsh0` are routed over QUIC streams directly to the target peer (or, as a last resort, relayed through the signal server).

Clusters configured under `~/.config/mlsh/clusters/` are auto-reconnected when `mlshtund` starts — no extra step needed beyond `mlsh setup` or `mlsh adopt`.

See [networking](@/networking/_index.md) for QUIC tunnels, NAT traversal, and DNS.

## Protocol versioning

Every client advertises a `PROTOCOL_VERSION` on handshake. The signal server rejects clients older than its `MIN_PROTOCOL_VERSION` at NodeAuth/Adopt. The client version is surfaced in the Nodes view, so you can tell which machines need an upgrade before bumping the signal. When upgrading, roll out nodes first if the new signal raises the minimum version.
