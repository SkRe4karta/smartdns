"""Verify and extract release archives without following links or trusting paths."""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


def unpack(archive: Path, destination: Path, *, allow_dirty: bool = False) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        names = set()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not member.isfile() or member.name in names:
                raise ValueError("Unsafe archive entry")
            names.add(member.name)
            total += member.size
            if member.size > 100_000_000 or total > 300_000_000:
                raise ValueError("Release archive exceeds size limit")
        manifest_file = bundle.extractfile("manifest.json")
        if not manifest_file:
            raise ValueError("Release has no manifest")
        manifest = json.load(manifest_file)
        if manifest.get("dirty") and not allow_dirty:
            raise ValueError("Uncommitted build cannot be deployed as a release")
        if set(manifest["files"]) | {"manifest.json"} != names:
            raise ValueError("Archive and manifest differ")
        for member in members:
            source = bundle.extractfile(member)
            if not source:
                raise ValueError("Unreadable archive entry")
            data = source.read()
            if (
                member.name != "manifest.json"
                and hashlib.sha256(data).hexdigest() != manifest["files"][member.name]
            ):
                raise ValueError("Release file checksum mismatch")
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            # The destination must be a newly allocated, private directory.
            if target.exists() or target.is_symlink():
                raise ValueError("Refusing to overwrite an existing extraction target")
            target.write_bytes(data)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    return manifest
