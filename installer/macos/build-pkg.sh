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

pkgbuild \
  --root "$PAYLOAD" \
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
