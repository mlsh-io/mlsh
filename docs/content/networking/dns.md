+++
title = "DNS"
description = "The per-node resolver that maps <node>.<cluster> to overlay IPs."
weight = 3
+++

Each node runs a minimal DNS resolver that answers for names inside its cluster. `ssh nas.homelab` works on every node in the cluster called `homelab`.

## What it resolves

- `<node>.<cluster>` → that node's overlay IP (A record).
- `<cluster>` alone → the local node's overlay IP.
- Anything else → `NXDOMAIN`.

TTL is 60 seconds. Lookups hit the in-memory peer table, which the daemon keeps in sync with the signal server.

## Listen address

- **Linux**: port `53` on the overlay IP.
- **macOS**: port `53535` on localhost (macOS reserves port 53 for `mDNSResponder`).
- **Windows**: port `53535` on localhost (Windows DNS client quirks).

## Split DNS integration

Only queries that match the cluster zone are routed to the MLSH resolver; everything else goes through the OS resolver unchanged.

- **macOS**: the daemon drops a file in `/etc/resolver/<cluster>` pointing at `127.0.0.1:53535`. `mDNSResponder` picks it up automatically.
- **Linux (systemd-resolved)**: the daemon configures `mlsh0` via D-Bus with `routing_only=true` and the cluster zone as the search domain.
- **Linux (non-systemd)**: fall back to editing `/etc/resolv.conf` or running a local resolver like `dnsmasq` that forwards the cluster zone to the MLSH resolver.
- **Windows**: `NRPT` (Name Resolution Policy Table) entries are added for the cluster zone.
