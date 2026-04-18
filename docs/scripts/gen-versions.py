#!/usr/bin/env python3
"""Regenerate versions.json, the `latest` symlink, and the root redirect
from the vX.Y.Z/ directories present in DIR.

Usage:
    gen-versions.py <dir>

Produces, under <dir>:
  - versions.json    consumed by docs/static/js/version-picker.js
  - latest           symlink to the newest vX.Y.Z/
  - index.html       meta-refresh redirect to /latest/
"""

import json
import os
import re
import sys


def main(root: str) -> int:
    if not os.path.isdir(root):
        print(f"error: {root!r} is not a directory", file=sys.stderr)
        return 1

    pattern = re.compile(r"^v(\d+)\.(\d+)\.(\d+)")
    versions = [
        name
        for name in os.listdir(root)
        if pattern.match(name) and os.path.isdir(os.path.join(root, name))
    ]

    def sort_key(v: str) -> tuple:
        m = pattern.match(v)
        return tuple(-int(x) for x in m.groups())  # type: ignore[union-attr]

    versions.sort(key=sort_key)

    payload = {
        "versions": [
            {"version": v, **({"latest": True} if i == 0 else {})}
            for i, v in enumerate(versions)
        ]
    }

    out_path = os.path.join(root, "versions.json")
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    print(f"wrote {out_path} with {len(versions)} version(s)")

    if versions:
        newest = versions[0]
        # `latest` -> newest vX.Y.Z/
        latest_link = os.path.join(root, "latest")
        if os.path.islink(latest_link) or os.path.exists(latest_link):
            os.remove(latest_link)
        os.symlink(newest, latest_link)
        print(f"linked {latest_link} -> {newest}")

        # Root index.html -> /latest/
        index_path = os.path.join(root, "index.html")
        with open(index_path, "w") as f:
            f.write(
                '<!doctype html><meta charset="utf-8">'
                '<title>MLSH Documentation</title>'
                '<meta http-equiv="refresh" content="0; url=/latest/">'
                '<link rel="canonical" href="/latest/">\n'
            )
        print(f"wrote {index_path} (redirect to /latest/)")

    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: gen-versions.py <dir>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
