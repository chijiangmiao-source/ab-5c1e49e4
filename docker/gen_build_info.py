#!/usr/bin/env python3
"""Emit the image build manifest consumed by the acceptance suite.

Walks every shipped file under the build context root and records a
single SHA-256 over their contents, along with the file list.  The
``verify`` service recomputes the digest inside the running image.
"""

import hashlib
import json
import os
import platform
import sys

SKIP_DIRS = {"__pycache__", ".git"}
SKIP_SUFFIXES = (".pyc", ".pyo")


def walk(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name.endswith(SKIP_SUFFIXES):
                continue
            yield os.path.join(dirpath, name)


def main(src_root):
    h = hashlib.sha256()
    rel_paths = []
    for path in sorted(walk(src_root)):
        rel = os.path.relpath(path, src_root)
        rel_paths.append(rel)
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        with open(path, "rb") as f:
            h.update(f.read())
        h.update(b"\0")
    manifest = {
        "image": "seabed-checkpoint",
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "file_count": len(rel_paths),
        "source_sha256": h.hexdigest(),
        "files": rel_paths,
    }
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
