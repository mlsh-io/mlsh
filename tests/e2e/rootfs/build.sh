#!/usr/bin/env bash
set -euo pipefail

WORK=/var/lib/mkosi-work
mkdir -p "$WORK/conf" "$WORK/workspace" "$WORK/cache" "$WORK/output"
cp /work/mkosi.conf "$WORK/conf/mkosi.conf"
cp -a /work/mkosi.skeleton "$WORK/conf/mkosi.skeleton" 2>/dev/null || true

cd "$WORK/conf"
mkosi \
    --force \
    --workspace-directory="$WORK/workspace" \
    --cache-directory="$WORK/cache" \
    --output-directory="$WORK/output" \
    build

mkdir -p /work/output
cp "$WORK/output"/*.raw /work/output/
