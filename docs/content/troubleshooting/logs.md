+++
title = "Reading Logs"
description = "Where MLSH writes logs and how to turn up verbosity."
weight = 2
+++

## Client / daemon

The daemon logs via `tracing`. Enable debug output with:

```sh
RUST_LOG=mlsh=debug,mlshtund=debug mlsh connect homelab --foreground
```

On background-mode runs, logs go to:

- **Linux**: `journalctl --user -u mlshtund` (if started via `systemd --user`) or `~/.local/state/mlsh/mlshtund.log`.
- **macOS**: `~/Library/Logs/mlsh/mlshtund.log`.
- **Windows**: `%LOCALAPPDATA%\mlsh\mlshtund.log`.

## Signal server

```sh
podman logs -f mlsh-signal
```

Raise verbosity with `RUST_LOG=mlsh_signal=debug`. JSON output is automatic when stdout is not a TTY.

## Reporting an issue

When filing a bug, please include:

1. `mlsh --version`.
2. The last ~200 lines of the daemon log at `debug` level.
3. Output of `mlsh status` and `mlsh nodes <cluster>`.
4. Rough description of the network topology on both ends (home NAT, corporate, cloud VM, etc.).

File at [github.com/mlsh-io/mlsh/issues](https://github.com/mlsh-io/mlsh/issues).
