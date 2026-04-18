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
cluster_name    = "homelab"
cluster_id      = "018f..."
node_id         = "01JA..."
node_name       = "nas"
role            = "node"
overlay_ip      = "100.64.0.3"

[signal]
host            = "signal.example.com"
port            = 4433
fingerprint     = "sha256:abc123..."
node_token      = "eyJ..."

[overlay]
subnet          = "100.64.0.0/10"
mtu             = 1400
```

You rarely need to edit this by hand.

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
