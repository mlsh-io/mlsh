+++
title = "Deployment"
description = "Run the signal server with Docker / Podman."
weight = 1
+++

The signal server needs a publicly reachable host, two open ports, and one volume for its SQLite database. That's it.

## Requirements

- A host reachable from the public internet (VPS, colocated server, or a Raspberry Pi behind your home router with UDP/443 and TCP/443 forwarded to it, anything with a stable public address). If you self-host behind a home router, the router must have a fixed public IP address from your ISP.
- **UDP/443** (QUIC signal) and **TCP/443** (TLS ingress) open inbound.
- A domain pointed at the host.

## Docker / Podman

The prebuilt container image is published on GitHub Container Registry at [`ghcr.io/mlsh-io/mlsh-signal:latest`](https://github.com/mlsh-io/mlsh/pkgs/container/mlsh-signal). Tagged releases (e.g. `:v0.3.0`) are published alongside `:latest`.

Create a minimal config file that binds both listeners to `:443`:

```toml
# /etc/mlsh-signal/config.toml
[quic]
bind = "0.0.0.0:443"

ingress_bind = "0.0.0.0:443"
```

Then run the container:

```sh
sudo podman run -d \
  --name mlsh-signal \
  -p 443:443/udp \
  -p 443:443/tcp \
  --cap-add=NET_BIND_SERVICE \
  -v mlsh-signal-data:/var/lib/mlsh-signal \
  -v /etc/mlsh-signal/config.toml:/etc/mlsh-signal/config.toml:ro \
  ghcr.io/mlsh-io/mlsh-signal:latest
```

Swap `podman` for `docker` if that is what you run; the arguments are identical.

## Create a cluster and setup token

Once the server is installed and running, create a cluster and generate a setup token with `mlsh-signal cluster create`.

```sh
sudo podman exec mlsh-signal /mlsh-signal cluster create myhomelab
```

Output:

```
Cluster created:
  Name:  myhomelab
  ID:    <UUID>

  Setup token: <CODE>@<UUID>@<FINGERPRINT>

  On a new machine:
    mlsh setup myhomelab --signal-host <host> --token <CODE>@<UUID>@<FINGERPRINT>
```

The setup token has three components joined by `@`:

- **`<CODE>`**: a 12-character human-readable code (grouped as `XXXX-XXXX-XXXX`). Single-use, expires after the TTL.
- **`<UUID>`**: the cluster's UUID. Pins the token to this specific cluster.
- **`<FINGERPRINT>`**: SHA-256 fingerprint of the signal server's TLS certificate. The client pins it at setup so that subsequent connections verify the server by fingerprint, not by CA chain.

The setup token is single-use and expires after **15 minutes** by default. Extend that window with `--ttl <minutes>`:

```sh
sudo podman exec mlsh-signal /mlsh-signal cluster create myhomelab --ttl 60
```

You can generate as many setup tokens as you need (one per cluster). Copy the printed `mlsh setup` line into a terminal on the first admin node. See [first connection](@/getting-started/first-connection.md) for the rest of the bootstrap flow.

## TLS

The server generates its TLS certificate on first boot and persists it in the database. Trust is established through fingerprint pinning: the SHA-256 fingerprint embedded in the setup token (`<FINGERPRINT>` above) is pinned by each node at adoption, so subsequent connections are verified by fingerprint rather than by a CA chain.

Continue to [configuration](@/signal-server/configuration.md) for all available settings.
