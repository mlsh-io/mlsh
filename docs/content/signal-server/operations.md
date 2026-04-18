+++
title = "Operations"
description = "Backup and upgrade the signal server."
weight = 3
+++

## Backup

The signal server's state lives entirely in its SQLite database (`/var/lib/mlsh-signal/signal.db` by default, overridable with `MLSH_SIGNAL_DB`). Stop the container and copy the file out:

```sh
sudo podman stop mlsh-signal
sudo podman cp mlsh-signal:/var/lib/mlsh-signal/signal.db ./signal.db.bak
sudo podman start mlsh-signal
```

Then copy `signal.db.bak` off the host.

## Upgrade

Pull the new image and restart. Schema migrations run automatically on startup.

```sh
podman pull ghcr.io/mlsh-io/mlsh-signal:latest
podman restart mlsh-signal
```

Rolling back to an older image after a migration is **not** supported.
