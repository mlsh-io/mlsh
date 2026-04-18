+++
title = "Configuration"
description = "TOML settings and environment variables for mlsh-signal."
weight = 2
+++

Configuration is loaded from a TOML file (default `/etc/mlsh-signal/config.toml`, overridable via `MLSH_SIGNAL_CONFIG`) and then overlaid with a handful of environment variables.

## Config file

All keys are optional; defaults are shown below.

```toml
# /etc/mlsh-signal/config.toml

# SQLite database path. Override with MLSH_SIGNAL_DB.
db_path = "/var/lib/mlsh-signal/signal.db"

# Overlay network subnet (CIDR). Nodes are allocated sequential IPs from this range.
overlay_subnet = "100.64.0.0/10"

# TCP bind for the TLS ingress listener.
ingress_bind = "0.0.0.0:443"

[quic]
# UDP address to bind for QUIC.
bind = "0.0.0.0:443"

# Optional. If omitted, the server generates its own TLS certificate on first
# boot and persists it in the database; clients verify it via fingerprint
# pinning embedded in the setup token.
# cert_path = "/etc/mlsh-signal/tls/fullchain.pem"
# key_path  = "/etc/mlsh-signal/tls/privkey.pem"
```

Binding on port 443 requires `CAP_NET_BIND_SERVICE` on the binary, which is granted automatically in a container that publishes `-p 443:443/tcp -p 443:443/udp`.

## Environment variables

Env vars override the corresponding config-file keys at process start.

| Variable | Default | Description |
|---|---|---|
| `MLSH_SIGNAL_CONFIG` | `/etc/mlsh-signal/config.toml` | Path to the TOML config file. |
| `MLSH_SIGNAL_DB` | `/var/lib/mlsh-signal/signal.db` | SQLite database path. Overrides `db_path`. |
| `MLSH_OVERLAY_SUBNET` | `100.64.0.0/10` | Overlay IP range (CIDR). Overrides `overlay_subnet`. |
| `RUST_LOG` | `mlsh_signal=info` | `tracing-subscriber` filter. |
