+++
title = "DNS"
description = "The per-node resolver that maps <node>.<cluster> to overlay IPs."
weight = 3
+++

Each node runs a minimal DNS resolver that answers for names inside its cluster. `ssh nas.homelab` works on every node in the cluster called `homelab`.

## What it resolves

- `<node-uuid>.<cluster>` → that node's overlay IP (`node_uuid` is a UUID v4).
- `<display-name>.<cluster>` → same overlay IP, using the human-readable name set via `mlsh rename`. The display name is sanitized to a valid DNS label (lowercase, `[a-z0-9-]`, separators become `-`, truncated to 63 chars). Examples: `Nico's Laptop` → `nicos-laptop.homelab`, `RPi 4 Garage` → `rpi-4-garage.homelab`.
- `<cluster>` alone → the **control-plane node** for the cluster (the one that runs the admin REST API and serves the UI). This is the canonical entry point for `mlsh ui` and for any client hitting the admin API over the overlay. When the local node *is* the control node, the resolver returns `127.0.0.1` instead of the overlay IP — macOS' utun does not loop packets back to the originating node, so loopback is the only address that works end-to-end.
- Anything else is not answered.

Resolution order: bare zone (`<cluster>`) → control node; then `node_uuid` match; then sanitized `display_name`. Renames (`mlsh rename`) propagate in real time — no TTL wait, no daemon restart.

TTL is 60 seconds. Lookups hit the in-memory peer table, which the daemon keeps in sync with the signal server.

## Bare names

The cluster is registered as a **search domain** on the OS, so you can drop the suffix:

```bash
ssh nas          # OS appends .homelab → nas.homelab → 100.64.0.5
ping pi          # same
```

Works on macOS (via `/etc/resolver/<cluster>`), Linux with systemd-resolved, and Windows (a connection-specific DNS suffix on the tunnel interface). On platforms without search-domain support, use the fully-qualified form.

## Listen address

- **Linux**: port `53` on the overlay IP.
- **macOS**: port `53535` on localhost (macOS reserves port 53 for `mDNSResponder`).
- **Windows**: port `53` on the overlay IP (NRPT can only target port 53 and refuses loopback addresses).

## Split DNS integration

Only queries that match the cluster zone are routed to the MLSH resolver; everything else goes through the OS resolver unchanged.

- **macOS**: the daemon drops a file in `/etc/resolver/<cluster>` pointing at `127.0.0.1:53535`. `mDNSResponder` picks it up automatically.
- **Linux (systemd-resolved)**: the daemon configures `mlsh0` via D-Bus, registering the cluster zone as both a routing target and a search domain (`routing_only=false`) so bare names are appended with `.<cluster>`.
- **Linux (non-systemd)**: fall back to editing `/etc/resolv.conf` or running a local resolver like `dnsmasq` that forwards the cluster zone to the MLSH resolver.
- **Windows**: `NRPT` (Name Resolution Policy Table) rules are added for the cluster zone via the DnsClient cmdlets — namespaces `.<cluster>` (subdomains) and `<cluster>` (the bare zone) point at the overlay resolver on `overlay-ip:53`. A connection-specific DNS suffix is also set on the tunnel interface so bare names resolve. Rules are tagged in their `Comment` field (`mlsh:<cluster>`) and removed on disconnect.
