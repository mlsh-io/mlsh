+++
title = "Connectivity"
description = "Diagnosing peer reachability issues."
weight = 1
+++

## 1. Check your own state

```sh
mlsh status
```

- **`connected`**: the signal session is up and you have peers. Continue to step 2.
- **`connecting`**: stuck here usually means UDP to the signal server is blocked. Check firewall rules on your network.
- **`disconnected`**: `mlsh connect <cluster>` never succeeded. Look at daemon logs (see [logs](@/troubleshooting/logs.md)).

## 2. Check the peer list

```sh
mlsh nodes homelab
```

Each peer shows a state:

- **`direct`**: QUIC tunnel established peer-to-peer. Nothing to diagnose.
- **`relay`**: direct path failed; traffic is going through the signal server. Slower but functional. Often caused by symmetric NAT on both sides.
- **`offline`**: the peer is not currently connected to the signal server. Nothing you can fix locally.

## 3. Ping the overlay

```sh
ping 100.64.0.4    # peer's overlay IP
```

If this fails but `mlsh nodes` shows the peer as `direct` or `relay`, the issue is likely inside the peer (firewall, `mlsh0` interface down, application binding to wrong interface).

## 4. DNS

```sh
dig @127.0.0.1 -p 53535 nas.homelab     # macOS / Windows
dig nas.homelab                          # Linux with systemd-resolved
```

If the A record comes back but `ssh nas.homelab` fails, it is a reachability issue, not a DNS one.

## 5. Common causes

| Symptom | Likely cause |
|---|---|
| Stuck `connecting` | UDP/4433 blocked between you and the signal host. |
| All peers `relay` | Both sides behind symmetric NAT. Works, but slow. Consider a port-forward on one side. |
| Peer `offline` immediately after adopt | The peer's daemon isn't running. `mlsh connect` on that machine. |
| `ssh nas.homelab` hangs | `mlsh0` MTU vs. path MTU. Try `ssh -o "IPQoS=none" nas.homelab` or lower the MTU. |
