+++
title = "DNS"
description = "The per-node resolver that maps <node>.<cluster> to overlay IPs."
weight = 3
+++

Each node runs a minimal DNS resolver that answers for names inside its cluster. `ssh nas.homelab` works on every node in the cluster called `homelab`.

## What it resolves

- `<node-id>.<cluster>` → that node's overlay IP.
- `<display-name>.<cluster>` → same overlay IP, using the human-readable name set via `mlsh rename`. The display name is sanitized to a valid DNS label (lowercase, `[a-z0-9-]`, separators become `-`, truncated to 63 chars). Examples: `Nico's Laptop` → `nicos-laptop.homelab`, `RPi 4 Garage` → `rpi-4-garage.homelab`.
- `<cluster>` alone → the local node's overlay IP.
- Anything else is not answered.

Resolution order: node_id first, then sanitized display_name. Renames (`mlsh rename`) propagate in real time — no TTL wait, no daemon restart.

TTL is 60 seconds. Lookups hit the in-memory peer table, which the daemon keeps in sync with the signal server.

## Bare names

The cluster is registered as a **search domain** on the OS, so you can drop the suffix:

```bash
ssh nas          # OS appends .homelab → nas.homelab → 100.64.0.5
ping pi          # same
```

Works on macOS (via `/etc/resolver/<cluster>`) and Linux with systemd-resolved. On platforms without search-domain support, use the fully-qualified form.

## Listen address

- **Linux**: port `53` on the overlay IP.
- **macOS**: port `53535` on localhost (macOS reserves port 53 for `mDNSResponder`).
- **Windows**: port `53535` on localhost (Windows DNS client quirks).

## Split DNS integration

Only queries that match the cluster zone are routed to the MLSH resolver; everything else goes through the OS resolver unchanged.

- **macOS**: the daemon drops a file in `/etc/resolver/<cluster>` pointing at `127.0.0.1:53535`. `mDNSResponder` picks it up automatically.
- **Linux (systemd-resolved)**: the daemon configures `mlsh0` via D-Bus, registering the cluster zone as both a routing target and a search domain (`routing_only=false`) so bare names are appended with `.<cluster>`.
- **Linux (non-systemd)**: fall back to editing `/etc/resolv.conf` or running a local resolver like `dnsmasq` that forwards the cluster zone to the MLSH resolver.
- **Windows**: `NRPT` (Name Resolution Policy Table) entries are added for the cluster zone.
