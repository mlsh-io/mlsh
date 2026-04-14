#!/bin/bash
set -euo pipefail

# Build an .rpm package for mlsh
# Usage: ./build-rpm.sh <version> <arch> <bindir>
#   version: e.g. v0.0.5
#   arch:    x86_64 or aarch64
#   bindir:  directory containing mlsh and mlshtund binaries

VERSION="${1:?usage: build-rpm.sh <version> <arch> <bindir>}"
ARCH="${2:?usage: build-rpm.sh <version> <arch> <bindir>}"
BINDIR="${3:?usage: build-rpm.sh <version> <arch> <bindir>}"

# Strip leading 'v' from version
VERSION="${VERSION#v}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUTPUT_DIR"

# -- Set up rpmbuild tree -----------------------------------------------------

mkdir -p "$WORK_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$WORK_DIR/BUILDROOT/usr/local/bin"

cp "$BINDIR/mlsh"    "$WORK_DIR/BUILDROOT/usr/local/bin/mlsh"
cp "$BINDIR/mlshtund" "$WORK_DIR/BUILDROOT/usr/local/bin/mlshtund"
chmod 755 "$WORK_DIR/BUILDROOT/usr/local/bin/mlsh" "$WORK_DIR/BUILDROOT/usr/local/bin/mlshtund"

# -- Write spec file ----------------------------------------------------------

cat > "$WORK_DIR/SPECS/mlsh.spec" <<SPEC
Name:    mlsh
Version: ${VERSION}
Release: 1
Summary: mlsh — mesh shell
License: Proprietary
URL:     https://mlsh.io
Group:   Applications/Internet

%description
Secure mesh networking CLI tool.

%install
mkdir -p %{buildroot}/usr/local/bin
cp %{_topdir}/BUILDROOT/usr/local/bin/mlsh    %{buildroot}/usr/local/bin/mlsh
cp %{_topdir}/BUILDROOT/usr/local/bin/mlshtund %{buildroot}/usr/local/bin/mlshtund

%files
%attr(755, root, root) /usr/local/bin/mlsh
%attr(755, root, root) /usr/local/bin/mlshtund
SPEC

# -- Build RPM ----------------------------------------------------------------

rpmbuild \
  --define "_topdir $WORK_DIR" \
  --target "$ARCH" \
  -bb "$WORK_DIR/SPECS/mlsh.spec"

cp "$WORK_DIR"/RPMS/"$ARCH"/*.rpm "$OUTPUT_DIR/"

echo "Built: $(ls "$OUTPUT_DIR"/*.rpm)"
