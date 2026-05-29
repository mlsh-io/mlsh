# mlsh-systray

A lightweight Windows system-tray control app for MLSH, built with **Qt 6 / C++
(QtWidgets, no QML)**. It is the Windows counterpart to the macOS `mlsh-menubar`
app: it shows tunnel status, lets you connect/disconnect clusters, and manages
the `mlshtund` Windows service.

The app talks to the `mlshtund` daemon directly over its control endpoint
(named pipe on Windows, via `QLocalSocket`) using the same length-prefixed JSON
protocol as the CLI — see `mlsh-cli/src/tund/control/protocol.rs`. It does **not**
link against any Rust binary.

## Features

- Tray icon tinted by connection state (green / orange / gray / red).
- Resizable window with:
  - status header,
  - **Windows service** panel (status + Install / Uninstall / Start / Stop, elevated via UAC),
  - active tunnels (name, overlay IP — click to copy, transport, uptime, ↑/↓ traffic, errors),
  - available clusters (one-click connect),
  - footer with version, GitHub update notice, and "Open config folder".
- Quick connect/disconnect and service control from the tray menu.

## Requirements / locations

- `mlsh.exe` / `mlshtund.exe` are expected **in the same folder** as
  `mlsh-systray.exe` (used for the service `install`/`uninstall` and `--version`).
- User config is read from `~/.config/mlsh/` (`clusters/*.toml`, `identity/{cert,key}.pem`),
  identical to the CLI on every platform.

## Build (Qt 6.11 MinGW kit)

The repo's Qt install is MinGW-only; the app needs no MSVC/ABI compatibility
with the Rust binaries since it speaks to the daemon over a pipe.

```powershell
$env:Path = "C:\Qt\6.11.0\mingw_64\bin;C:\Qt\Tools\mingw1310_64\bin;C:\Qt\Tools\CMake_64\bin;$env:Path"
cmake -S mlsh-systray -B mlsh-systray/build -G "MinGW Makefiles" -DCMAKE_PREFIX_PATH="C:/Qt/6.11.0/mingw_64"
cmake --build mlsh-systray/build
```

The binary is `mlsh-systray/build/mlsh-systray.exe`.

## Deploy

```powershell
cmake --build mlsh-systray/build --target deploy   # runs windeployqt
# or manually:
windeployqt --no-translations mlsh-systray/build/mlsh-systray.exe
```

Then copy `mlsh.exe` and `mlshtund.exe` next to `mlsh-systray.exe`.

## Packaging

CI builds the app with the Qt MinGW kit, runs `windeployqt`, and the result is
bundled into the existing Windows installer (`installer/windows/mlsh.iss`)
alongside `mlsh.exe`/`mlshtund.exe`. The installer adds a Start Menu shortcut,
an optional login autostart, and can launch the tray app on finish. See the
`windows-systray` job in `.github/workflows/mlsh-{cli,release}.yml`.

The embedded executable icon lives in `resources/app.ico` (built into the exe
via `resources/app.rc`). Regenerate it after changing the logo:

```powershell
pwsh -File resources/generate-icon.ps1
```

## Modules

- `ipc/` — protocol (JSON) + `DaemonClient` (named-pipe IPC, 4-byte big-endian framing).
- `model/` — `TunnelStatus` DTO and `AppState` (polling, request queue, observable state).
- `config/` — cluster discovery and identity/config file reading.
- `service/` — `ServiceController` (SCM read-only status + UAC-elevated actions).
- `update/` — GitHub Releases update checker.
- `ui/` — `MainWindow`, `TrayIcon`, `TunnelRow`, programmatic logo `IconFactory`, theme.

## Linux port (later)

Platform-specific bits are isolated behind `#ifdef`:

- `DaemonClient::defaultEndpoints()` already returns Unix socket paths off-Windows.
- `ServiceController` is a stub off-Windows (systemd integration TBD).

The protocol, models, and UI are platform-agnostic.
