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
- An **overlay IP**: allocated by the signal server from the cluster's subnet (default `100.64.0.0/10`).
- A **node name**: e.g. `nas`, `laptop`, `gateway`. Combined with the cluster name it becomes a DNS name: `nas.homelab`.
- A **role**: `admin` (can invite new nodes) or `node` (regular member).

## Signal server

A single lightweight Rust binary (shipped as a container). It handles:

- Node registration and peer discovery.
- Invite verification.
- Relay fallback when direct connectivity fails.

It is **not** on the data path for healthy connections. Peers punch through NAT and talk directly once discovery is done.

## Sponsorship

MLSH has no shared secret for ongoing membership. The cluster secret is used **once** to bootstrap the first admin. After that, new nodes join through **sponsorship**: an existing admin signs an invite, the new node presents it, and the signal server verifies the signature against the sponsor's public key.

This creates a verifiable trust chain: every node was either the original admin or was explicitly vouched for by an existing one. See [trust model](@/security/trust-model.md) for details.

## Overlay network

When a node connects, the daemon creates a TUN device named `mlsh0` with the node's overlay IP. Packets written to `mlsh0` are routed over QUIC streams directly to the target peer (or, as a last resort, relayed through the signal server).

See [networking](@/networking/_index.md) for QUIC tunnels, NAT traversal, and DNS.
