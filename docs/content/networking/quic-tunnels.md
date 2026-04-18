+++
title = "QUIC Tunnels"
description = "Why QUIC, how streams map to packets, and the TUN device lifecycle."
weight = 1
+++

## Why QUIC

QUIC runs over UDP, multiplexes streams, and bakes in TLS 1.3. Three things MLSH gets for free:

- **Fast connection setup.** 1-RTT handshake (0-RTT on reconnect), no TCP three-way handshake before TLS.
- **Stream multiplexing.** One QUIC connection can carry many independent streams without head-of-line blocking between them.
- **A clean hook for post-quantum.** TLS 1.3 in QUIC is the same TLS 1.3 as everywhere else, so plugging in [X25519Kyber768](@/security/cryptography.md) is free.

## Two connections per peer

For any peer relationship, MLSH maintains two distinct QUIC connections:

1. **Signal connection**: from each node to the signal server, for coordination (peer discovery, heartbeats, relay fallback).
2. **Peer connection**: directly from node A to node B, carrying the actual overlay traffic.

The signal server is not on the fast path. Once peers have found each other and punched through NAT, their traffic flows directly.

## Packet pipeline

```
userspace app → mlsh0 (TUN) → mlshtund → QUIC stream → UDP → peer's UDP
                                                           ↓
                                                     QUIC stream
                                                           ↓
                                                     mlshtund → mlsh0 → userspace app
```

Packets written to `mlsh0` are read by the daemon, matched against the in-memory routing table by destination overlay IP, and written to a unidirectional QUIC stream to the right peer.

## TUN device

The daemon creates a TUN interface named `mlsh0`:

- **MTU**: 1400 bytes, to leave room for QUIC + UDP encapsulation on a standard 1500-byte link.
- **IP**: the node's overlay IP (for example `100.64.0.3/10`).
- **Lifecycle**: created when `mlsh connect` runs, destroyed on `mlsh disconnect` or daemon exit.

On Linux, this requires `CAP_NET_ADMIN`; the installer sets the capability on the daemon binary so non-root users can connect. On macOS, `utun` is used; on Windows, the WinTun driver.
