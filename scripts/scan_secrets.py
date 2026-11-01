#!/usr/bin/env python3
"""Run a pinned Gitleaks binary against tracked and not-yet-committed source files."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

VERSION = "8.30.1"
SHA256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
URL = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_linux_x64.tar.gz"


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    cache = root / "work/security-tools"
    cache.mkdir(parents=True, exist_ok=True)
    binary = cache / "gitleaks"
    # Re-verify the downloaded archive before every extraction, including cache hits.
    archive = cache / f"gitleaks-{VERSION}.tar.gz"
    if not archive.exists():
        with urllib.request.urlopen(URL, timeout=45) as response:  # noqa: S310 -- fixed HTTPS upstream
            data = response.read(30_000_001)
        if len(data) > 30_000_000:
            raise ValueError("Scanner archive too large")
        archive.write_bytes(data)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise ValueError("Scanner checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive.read_bytes()), mode="r:gz") as bundle:
        item = bundle.extractfile("gitleaks")
        if item is None:
            raise ValueError("Scanner missing")
        binary.write_bytes(item.read())
        binary.chmod(0o755)
    source = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    with tempfile.TemporaryDirectory(prefix="zelyonka-secrets-") as directory:
        destination = Path(directory)
        for raw in source.split(b"\0"):
            if not raw:
                continue
            name = Path(os.fsdecode(raw))
            original = root / name
            if original.is_symlink():
                raise ValueError("Source symlinks are not accepted")
            if not original.is_file():
                continue
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        subprocess.run(
            [
                str(binary),
                "dir",
                str(destination),
                "--redact",
                "--no-banner",
                "--config",
                str(root / ".gitleaks.toml"),
            ],
            check=True,
            cwd=root,
        )


if __name__ == "__main__":
    main()
