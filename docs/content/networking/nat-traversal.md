+++
title = "NAT Traversal"
description = "Candidate gathering, happy-eyeballs probing, and relay fallback."
weight = 2
+++

MLSH reaches peers through NAT using an [ICE](https://datatracker.ietf.org/doc/rfc8445/)-inspired approach: each node advertises its reachable addresses as **candidates**, and peers race them to find the first one that works.

## Candidate gathering

When a node connects to the signal server, the daemon enumerates local network addresses and reports them. Before advertising, it filters out:

- loopback (`127.0.0.0/8`, `::1`),
- link-local (`169.254.0.0/16`, `fe80::/10`),
- Docker / Podman bridge networks,
- the overlay subnet itself, to prevent routing loops.

The signal server may augment the list with the node's observed public address (from the UDP source of its signal connection). This is called a server-reflexive candidate in ICE parlance.

## Probing: happy eyeballs

When a new peer appears, the daemon probes the peer's candidates using [RFC 8305](https://datatracker.ietf.org/doc/rfc8305/)-style happy eyeballs: it starts a QUIC connection attempt to each address with staggered 100 ms delays and keeps the first one to complete.

A deterministic tiebreaker (the node with the **lower overlay IP** initiates) prevents both sides from simultaneously opening duplicate relay streams.

## Relay fallback

If every direct candidate fails (symmetric-NAT-on-symmetric-NAT, aggressive firewall, carrier-grade NAT), the daemon falls back to **relaying** through the signal server. Packets are wrapped in a relay stream and the server forwards them to the destination node's own signal connection.

Relay is bandwidth-capped (`relay.max_rate_kbps` in `mlsh-signal` config) to prevent the server from becoming a free VPN gateway. Direct connections are retried periodically; once a direct path works, the relay stream is torn down.

`mlsh nodes <cluster>` shows whether each peer is connected `direct` or `relay`.
