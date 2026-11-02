#!/usr/bin/env python3
"""Build a commit-specific, checksummed application artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path


def run(args: list[str], **kwargs) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="dist")
    parser.add_argument("--uv", default="uv")
    parser.add_argument("--allow-dirty", action="store_true", help="Preflight only; cannot be released")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    commit = run(["git", "rev-parse", "HEAD"])
    dirty = bool(run(["git", "status", "--porcelain"]))
    if dirty and not args.allow_dirty:
        raise SystemExit("Commit all source changes before producing a release artifact")
    epoch = int(run(["git", "show", "-s", "--format=%ct", "HEAD"]))
    version = root.joinpath("VERSION").read_text().strip()
    if version != "0.3.0-rc.1":
        raise SystemExit("Unexpected release version")
    if not root.joinpath("frontend/dist/index.html").is_file():
        raise SystemExit("Build the frontend first")
    files: dict[str, tuple[bytes, int]] = {}
    for folder in ["src", "config", "docs", "scripts", "frontend/dist"]:
        for path in sorted(root.joinpath(folder).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo"):
                files[path.relative_to(root).as_posix()] = (path.read_bytes(), path.stat().st_mode)
    for name in [
        ".python-version",
        ".node-version",
        "README.md",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "SECURITY.md",
        "VERSION",
        "pyproject.toml",
        "uv.lock",
        "requirements.txt",
        "frontend/package.json",
        "frontend/package-lock.json",
    ]:
        path = root / name
        files[name] = (path.read_bytes(), path.stat().st_mode)
    with tempfile.TemporaryDirectory(prefix="smartdns-wheel-") as directory:
        run(
            [args.uv, "build", "--wheel", "--out-dir", directory],
            env=os.environ | {"SOURCE_DATE_EPOCH": str(epoch)},
        )
        wheels = list(Path(directory).glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError("Expected exactly one application wheel")
        files["wheels/" + wheels[0].name] = (wheels[0].read_bytes(), 0o644)
    manifest = {
        "version": version,
        "commit": commit,
        "dirty": dirty,
        "source_date_epoch": epoch,
        "files": {name: hashlib.sha256(data).hexdigest() for name, (data, _) in sorted(files.items())},
    }
    files["manifest.json"] = (json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n", 0o644)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"smartdns-dns-{version}-{commit[:12]}.tar.gz"
    with (
        archive.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped,
        tarfile.open(fileobj=zipped, mode="w") as bundle,
    ):
        for name, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if mode & 0o111 else 0o644
            info.mtime = epoch
            bundle.addfile(info, io.BytesIO(data))
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text(f"{checksum}  {archive.name}\n")
    print(json.dumps({"artifact": str(archive), "sha256": checksum, "commit": commit, "dirty": dirty}))


if __name__ == "__main__":
    main()
