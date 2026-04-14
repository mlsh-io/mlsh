#!/bin/bash
set -euo pipefail

# Build a macOS .pkg installer for MLSH (CLI + menubar app)
# Binaries live inside MLSH.app; symlinks in /usr/local/bin point into the bundle.
#
# Usage: ./build-pkg.sh <version> <path-to-MLSH.app>

VERSION="${1:?usage: build-pkg.sh <version> <path-to-MLSH.app>}"
APP_PATH="${2:?usage: build-pkg.sh <version> <path-to-MLSH.app>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PKG_ID="io.mlsh.pkg"
OUTPUT_DIR="${SCRIPT_DIR}/output"
OUTPUT_NAME="mlsh-${VERSION}-macos-universal.pkg"

mkdir -p "$OUTPUT_DIR"

# -- Prepare payload ----------------------------------------------------------

PAYLOAD="${WORK_DIR}/payload"
mkdir -p "$PAYLOAD/Applications"
mkdir -p "$PAYLOAD/usr/local/bin"

cp -R "$APP_PATH" "$PAYLOAD/Applications/MLSH.app"

ln -sf /Applications/MLSH.app/Contents/MacOS/mlsh    "$PAYLOAD/usr/local/bin/mlsh"
ln -sf /Applications/MLSH.app/Contents/MacOS/mlshtund "$PAYLOAD/usr/local/bin/mlshtund"

echo "App bundle contents:"
ls -la "$PAYLOAD/Applications/MLSH.app/Contents/MacOS/"

# -- Build component pkg ------------------------------------------------------

# Write a component plist that disables bundle relocation
cat > "${WORK_DIR}/component.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <dict>
        <key>BundleHasStrictIdentifier</key>
        <true/>
        <key>BundleIsRelocatable</key>
        <false/>
        <key>BundleIsVersionChecked</key>
        <false/>
        <key>BundleOverwriteAction</key>
        <string>upgrade</string>
        <key>RootRelativeBundlePath</key>
        <string>Applications/MLSH.app</string>
    </dict>
</array>
</plist>
PLIST

# Write postinstall script to install and start the LaunchDaemon
SCRIPTS_DIR="${WORK_DIR}/scripts"
mkdir -p "$SCRIPTS_DIR"
cat > "$SCRIPTS_DIR/postinstall" <<'POSTINSTALL'
#!/bin/bash
set -e

LABEL="io.mlsh.tund"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
MLSHTUND="/Applications/MLSH.app/Contents/MacOS/mlshtund"
LOG_DIR="/var/log/mlsh"

mkdir -p "$LOG_DIR"

# Unload if already running
launchctl unload "$PLIST" 2>/dev/null || true

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${MLSHTUND}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/mlshtund.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/mlshtund.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>mlsh_cli=info</string>
    </dict>
</dict>
</plist>
EOF

launchctl load "$PLIST"
POSTINSTALL
chmod +x "$SCRIPTS_DIR/postinstall"

pkgbuild \
  --root "$PAYLOAD" \
  --component-plist "${WORK_DIR}/component.plist" \
  --scripts "$SCRIPTS_DIR" \
  --identifier "$PKG_ID" \
  --version "${VERSION#v}" \
  --install-location "/" \
  "${WORK_DIR}/mlsh-component.pkg"

# -- Build product pkg with distribution --------------------------------------

cat > "${WORK_DIR}/distribution.xml" <<DIST
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>mlsh ${VERSION}</title>
    <welcome language="en" mime-type="text/plain"><![CDATA[
mlsh creates peer-to-peer encrypted overlay networks between your machines.

This installer will place:
  - MLSH.app in /Applications
  - mlsh and mlshtund in /usr/local/bin
    ]]></welcome>
    <options customize="never" require-scripts="false" hostArchitectures="x86_64,arm64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <choices-outline>
        <line choice="default"/>
    </choices-outline>
    <choice id="default" title="mlsh">
        <pkg-ref id="${PKG_ID}"/>
    </choice>
    <pkg-ref id="${PKG_ID}" version="${VERSION#v}" onConclusion="none">mlsh-component.pkg</pkg-ref>
</installer-gui-script>
DIST

productbuild \
  --distribution "${WORK_DIR}/distribution.xml" \
  --package-path "$WORK_DIR" \
  "${OUTPUT_DIR}/${OUTPUT_NAME}"

echo "Built: ${OUTPUT_DIR}/${OUTPUT_NAME}"
