+++
title = "Installation"
description = "Install the MLSH client on Linux, macOS, or Windows."
weight = 1
+++

MLSH ships as a single static binary that provides both the client (`mlsh`) and the tunnel daemon (`mlshtund`).

## Linux

```sh
curl -fsSL https://install.mlsh.io | sh
```

The installer detects your architecture (x86_64 / aarch64), downloads the latest release, and symlinks `mlsh` and `mlshtund` into `/usr/local/bin`.

An alternative is to use the `.deb`, `.rpm`, or `.tgz` package that matches your distribution, attached to each [release](https://github.com/mlsh-io/mlsh/releases).

## macOS

Download the universal installer `mlsh-vX.Y.Z-macos-universal.pkg` from the [GitHub Releases](https://github.com/mlsh-io/mlsh/releases) page. The package places `mlsh` and `mlshtund` in `/usr/local/bin` along with the menu bar app.

The package is not yet signed or notarized, so macOS Gatekeeper will block it on first launch. To accept it:

1. Double-click the `.pkg`. You will see a message that it "cannot be opened because Apple cannot check it for malicious software." Dismiss the dialog.
2. Open **System Settings → Privacy & Security**, scroll to the Security section, and click **Open Anyway** next to the blocked installer.
3. Confirm with your admin password.

Alternatively, from the terminal:

```sh
xattr -dr com.apple.quarantine ~/Downloads/mlsh-vX.Y.Z-macos-universal.pkg
sudo installer -pkg ~/Downloads/mlsh-vX.Y.Z-macos-universal.pkg -target /
```

If you only need the CLI, install it with the one-liner:

```sh
curl -fsSL https://install.mlsh.io | sh
```

## Windows

Download `mlsh-vX.Y.Z-windows-amd64-setup.exe` from the [GitHub Releases](https://github.com/mlsh-io/mlsh/releases) page and double-click it. The Inno Setup wizard guides you through installation and adds `mlsh` and `mlshtund` to your `PATH`.

The installer is not yet signed, so Windows SmartScreen will warn on first launch. Click **More info → Run anyway** to proceed.

## Verify the install

```sh
mlsh --version
```

## What's next

Continue to [First Connection](@/getting-started/first-connection.md) to bootstrap your first cluster.
