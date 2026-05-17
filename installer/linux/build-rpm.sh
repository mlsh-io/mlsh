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
# RPM forbids '-' in Version (reserved as Version-Release separator). Translate
# pre-release suffixes like 0.0.0-ci → 0.0.0_ci so non-tagged CI builds work.
VERSION="${VERSION//-/_}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUTPUT_DIR"

# -- Set up rpmbuild tree -----------------------------------------------------

mkdir -p "$WORK_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$WORK_DIR/BUILDROOT/usr/local/bin"
mkdir -p "$WORK_DIR/BUILDROOT/lib/systemd/system"
mkdir -p "$WORK_DIR/BUILDROOT/etc/mlsh"

cp "$BINDIR/mlsh"    "$WORK_DIR/BUILDROOT/usr/local/bin/mlsh"
cp "$BINDIR/mlshtund" "$WORK_DIR/BUILDROOT/usr/local/bin/mlshtund"
chmod 755 "$WORK_DIR/BUILDROOT/usr/local/bin/mlsh" "$WORK_DIR/BUILDROOT/usr/local/bin/mlshtund"
cp "$SCRIPT_DIR/mlshtund.service"     "$WORK_DIR/BUILDROOT/lib/systemd/system/mlshtund.service"
cp "$SCRIPT_DIR/mlsh-cloud-pubkey.pem" "$WORK_DIR/BUILDROOT/etc/mlsh/mlsh-cloud-pubkey.pem"

# -- Write spec file ----------------------------------------------------------

cat > "$WORK_DIR/SPECS/mlsh.spec" <<SPEC
Name:    mlsh
Version: ${VERSION}
Release: 1
Summary: mlsh — peer-to-peer encrypted overlay networks
License: Proprietary
URL:     https://mlsh.io
Group:   Applications/Internet
Requires: systemd

%description
mlsh creates peer-to-peer encrypted overlay networks between your machines.

%install
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/lib/systemd/system
mkdir -p %{buildroot}/etc/mlsh
cp %{_topdir}/BUILDROOT/usr/local/bin/mlsh    %{buildroot}/usr/local/bin/mlsh
cp %{_topdir}/BUILDROOT/usr/local/bin/mlshtund %{buildroot}/usr/local/bin/mlshtund
cp %{_topdir}/BUILDROOT/lib/systemd/system/mlshtund.service %{buildroot}/lib/systemd/system/mlshtund.service
cp %{_topdir}/BUILDROOT/etc/mlsh/mlsh-cloud-pubkey.pem      %{buildroot}/etc/mlsh/mlsh-cloud-pubkey.pem

%files
%attr(755, root, root) /usr/local/bin/mlsh
%attr(755, root, root) /usr/local/bin/mlshtund
%attr(644, root, root) /lib/systemd/system/mlshtund.service
%attr(644, root, root) /etc/mlsh/mlsh-cloud-pubkey.pem

%post
if [ \$1 -eq 1 ]; then
    systemctl daemon-reload || true
    systemctl enable --now mlshtund.service || true
fi

%preun
if [ \$1 -eq 0 ]; then
    systemctl disable --now mlshtund.service || true
fi
SPEC

# -- Build RPM ----------------------------------------------------------------

rpmbuild \
  --define "_topdir $WORK_DIR" \
  --target "$ARCH" \
  -bb "$WORK_DIR/SPECS/mlsh.spec"

cp "$WORK_DIR"/RPMS/"$ARCH"/*.rpm "$OUTPUT_DIR/"

echo "Built: $(ls "$OUTPUT_DIR"/*.rpm)"
