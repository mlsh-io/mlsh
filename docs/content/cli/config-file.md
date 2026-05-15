+++
title = "Configuration File"
description = "Layout of ~/.config/mlsh/: clusters, identity, and daemon settings."
weight = 2
+++

Everything the CLI and daemon need lives under `~/.config/mlsh/` on Linux and macOS, and `%APPDATA%\mlsh\` on Windows.

## Layout

```
~/.config/mlsh/
  identity/
    ed25519.key          # node private key (0600)
    ed25519.pub          # node public key
  clusters/
    homelab.toml         # one file per cluster
    prod.toml
  daemon.toml            # optional daemon-wide settings
```

## Cluster file

Each `clusters/<name>.toml` is written by `mlsh setup` or `mlsh adopt`. Example:

```toml
[cluster]
name              = "homelab"
id                = "9c5e4a1e-..."   # UUID v4
signal_endpoint   = "signal.example.com:4433"
signal_fingerprint = "sha256:abc123..."
zone              = "homelab.example.com"   # public DNS zone, optional

[node_auth]
node_uuid         = "3a1b7c9e-..."   # UUID v4
display_name      = "nas"
fingerprint       = "sha256:def456..."
roles             = ["node"]          # add "control" on the control-plane node

[overlay]
ip                = "100.64.0.3"
subnet            = "100.64.0.0/10"
```

You rarely need to edit this by hand. `mlsh control promote` / `demote` manage the `roles` array in place.

## Daemon file (optional)

```toml
log_level   = "info"       # error | warn | info | debug | trace
metrics     = false        # expose Prometheus on 127.0.0.1:9464 if true
```

## Environment overrides

| Variable | Effect |
|---|---|
| `MLSH_CONFIG_DIR` | Overrides the config directory root. |
| `RUST_LOG` | Standard `tracing-subscriber` filter (takes precedence over `log_level`). |
