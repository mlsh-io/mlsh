#!/bin/bash
set -euo pipefail

# Build a .deb package for mlsh
# Usage: ./build-deb.sh <version> <arch> <bindir>
#   version: e.g. v0.0.5
#   arch:    amd64 or arm64
#   bindir:  directory containing mlsh and mlshtund binaries

VERSION="${1:?usage: build-deb.sh <version> <arch> <bindir>}"
ARCH="${2:?usage: build-deb.sh <version> <arch> <bindir>}"
BINDIR="${3:?usage: build-deb.sh <version> <arch> <bindir>}"

# Strip leading 'v' from version
VERSION="${VERSION#v}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
PKG_NAME="mlsh_${VERSION}_${ARCH}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUTPUT_DIR"

# -- Build directory structure ------------------------------------------------

ROOT="${WORK_DIR}/${PKG_NAME}"

# Binaries
mkdir -p "$ROOT/usr/local/bin"
cp "$BINDIR/mlsh"    "$ROOT/usr/local/bin/mlsh"
cp "$BINDIR/mlshtund" "$ROOT/usr/local/bin/mlshtund"
chmod 755 "$ROOT/usr/local/bin/mlsh" "$ROOT/usr/local/bin/mlshtund"

# systemd unit + mlsh-cloud JWT pubkey
mkdir -p "$ROOT/lib/systemd/system" "$ROOT/etc/mlsh"
cp "$SCRIPT_DIR/mlshtund.service"     "$ROOT/lib/systemd/system/mlshtund.service"
cp "$SCRIPT_DIR/mlsh-cloud-pubkey.pem" "$ROOT/etc/mlsh/mlsh-cloud-pubkey.pem"
chmod 644 "$ROOT/lib/systemd/system/mlshtund.service" "$ROOT/etc/mlsh/mlsh-cloud-pubkey.pem"

# Control file
mkdir -p "$ROOT/DEBIAN"
cat > "$ROOT/DEBIAN/control" <<CTRL
Package: mlsh
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: mlsh.io <hello@mlsh.io>
Description: mlsh — peer-to-peer encrypted overlay networks
 mlsh creates peer-to-peer encrypted overlay networks between your machines.
Homepage: https://mlsh.io
Section: net
Priority: optional
CTRL

cat > "$ROOT/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable --now mlshtund.service || true
fi
POST
chmod 755 "$ROOT/DEBIAN/postinst"

cat > "$ROOT/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl disable --now mlshtund.service || true
fi
PRERM
chmod 755 "$ROOT/DEBIAN/prerm"

# -- Build .deb ---------------------------------------------------------------

dpkg-deb --build --root-owner-group "$ROOT" "${OUTPUT_DIR}/${PKG_NAME}.deb"

echo "Built: ${OUTPUT_DIR}/${PKG_NAME}.deb"
