#!/usr/bin/env python3
"""Describe the repository recipe and content inputs of the selected image build."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys


ROOT_INPUTS = (".dockerignore", "Dockerfile", "go.mod", "go.sum", "provider", "integration")

UI_INPUTS = (".dockerignore", "ui", "integration/upstream.env", "integration/build.sh",
             "integration/source-metadata.py", "integration/artifact-metadata.py")


def source_hash(root, inputs=ROOT_INPUTS):
    files = []
    for name in inputs:
        path = root / name
        if path.is_dir():
            files.extend(p for p in path.rglob("*") if p.is_file() or p.is_symlink())
        elif path.is_file():
            files.append(path)
        else:
            raise ValueError("missing Docker source input: " + name)
    digest = hashlib.sha256(b"esignet-candidate-source-v1\0")
    for path in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        if path.is_symlink():
            kind, executable, content = b"symlink", b"0", os.readlink(path).encode()
        else:
            kind = b"file"
            executable = b"1" if path.stat().st_mode & 0o111 else b"0"
            content = path.read_bytes()
        for part in (kind, relative, executable, str(len(content)).encode(), content):
            digest.update(part)
            digest.update(b"\0")
    return digest.hexdigest()


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--ui"):
        raise SystemExit("usage: source-metadata.py ROOT [--ui]")
    root = Path(sys.argv[1]).resolve()
    inputs = UI_INPUTS if len(sys.argv) == 3 else ROOT_INPUTS
    try:
        revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        status = subprocess.check_output(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal", "--", *inputs], text=True, stderr=subprocess.DEVNULL)
        state = "dirty" if status else "clean"
    except subprocess.CalledProcessError:
        revision, state = "unknown", "unrecorded"
    print(source_hash(root, inputs), revision, state)


if __name__ == "__main__":
    main()
