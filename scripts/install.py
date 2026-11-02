#!/usr/bin/env python3
"""Install a verified artifact with a private, consistent backup and explicit rollback.

Configure the ingress, filtering component, firewall and service units first using
config/templates. This script never replaces a shared ingress configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from release_tools import unpack


def run(args: list[str], **kwargs) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=120, **kwargs).stdout


def snapshot(source: Path, destination: Path) -> None:
    with (
        sqlite3.connect(f"file:{source}?mode=ro", uri=True) as origin,
        sqlite3.connect(destination) as target,
    ):
        origin.backup(target)
    destination.chmod(0o600)


def switch(root: Path, release: Path) -> None:
    temporary = root / "current.new"
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(release)
    temporary.replace(root / "current")


def rollback(root: Path, backup: Path, units: list[str]) -> None:
    state = json.loads((backup / "restore.json").read_text())
    if state["root"] != str(root) or state["units"] != units:
        raise ValueError("Backup belongs to another installation")
    run(["systemctl", "stop", *units])
    config = json.loads((backup / "settings.json").read_text())
    db = Path(config["data_dir"]) / "application.sqlite3"
    for suffix in ("", "-wal", "-shm"):
        Path(str(db) + suffix).unlink(missing_ok=True)
    if (backup / "database.sqlite3").exists():
        shutil.copy2(backup / "database.sqlite3", db)
        os.chown(db, state["db_uid"], state["db_gid"])
        db.chmod(0o660)
    shutil.copy2(backup / "settings.json", state["settings"])
    if (backup / "master.key").exists():
        shutil.copy2(backup / "master.key", config["master_key_file"])
        Path(config["master_key_file"]).chmod(0o600)
    if (backup / "installed.json").exists():
        shutil.copy2(backup / "installed.json", root / "installed.json")
    else:
        (root / "installed.json").unlink(missing_ok=True)
    if state["previous"]:
        switch(root, Path(state["previous"]))
        run(["systemctl", "start", *units])
    else:
        (root / "current").unlink(missing_ok=True)
    print("Previous application and database restored; ingress and certificate configuration retained")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/opt/smartdns"))
    parser.add_argument("--settings", type=Path, default=Path("/etc/smartdns/settings.json"))
    parser.add_argument("--units", nargs=3, default=["smartdns-api", "smartdns-gateway", "smartdns-agent"])
    command = parser.add_subparsers(dest="action", required=True)
    install = command.add_parser("apply")
    install.add_argument("artifact", type=Path)
    install.add_argument("--sha256", required=True)
    install.add_argument("--commit", required=True)
    install.add_argument("--uv", default="uv")
    restore = command.add_parser("rollback")
    restore.add_argument("backup", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("Run as root")
    os.umask(0o077)
    root = args.root.resolve()
    if args.action == "rollback":
        rollback(root, args.backup.resolve(), args.units)
        return
    if hashlib.sha256(args.artifact.read_bytes()).hexdigest() != args.sha256:
        raise ValueError("Artifact checksum mismatch")
    config = json.loads(args.settings.read_text())
    key = Path(config["master_key_file"])
    db = Path(config["data_dir"]) / "application.sqlite3"
    if db.exists() and not key.is_file():
        raise ValueError("Restore the matching master encryption key before upgrading")
    release = root / "releases" / args.commit
    if release.exists():
        raise ValueError("Release directory already exists; do not reuse a partially prepared release")
    manifest = unpack(args.artifact, release)
    if manifest["commit"] != args.commit:
        raise ValueError("Artifact commit mismatch")
    run([args.uv, "venv", "--python", "3.14.4", str(release / "venv")])
    python = str(release / "venv/bin/python")
    run(
        [
            args.uv,
            "pip",
            "install",
            "--python",
            python,
            "--require-hashes",
            "-r",
            str(release / "requirements.txt"),
        ]
    )
    run(
        [
            args.uv,
            "pip",
            "install",
            "--python",
            python,
            "--no-deps",
            str(next((release / "wheels").glob("*.whl"))),
        ]
    )
    for path in [release, *release.rglob("*")]:
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = root / "backups" / stamp
    backup.mkdir(parents=True, mode=0o700)
    previous = str((root / "current").resolve()) if (root / "current").exists() else None
    state = {
        "root": str(root),
        "previous": previous,
        "settings": str(args.settings.resolve()),
        "units": args.units,
        "db_uid": db.stat().st_uid if db.exists() else Path(config["data_dir"]).stat().st_uid,
        "db_gid": db.stat().st_gid if db.exists() else Path(config["data_dir"]).stat().st_gid,
    }
    if (root / "installed.json").exists():
        shutil.copy2(root / "installed.json", backup / "installed.json")
    shutil.copy2(args.settings, backup / "settings.json")
    if key.exists():
        shutil.copy2(key, backup / "master.key")
        (backup / "master.key").chmod(0o600)
    # Stop all database writers before the backup. DNS/proxy access fails closed during this short window.
    run(["systemctl", "stop", *args.units])
    if db.exists():
        snapshot(db, backup / "database.sqlite3")
    (backup / "restore.json").write_text(json.dumps(state, indent=2))
    (root / "rollback-location").write_text(str(backup) + "\n")
    try:
        env = os.environ | {"SMARTDNS_CONFIG": str(args.settings)}
        env.pop("CREDENTIALS_DIRECTORY", None)
        run([str(release / "venv/bin/smartdns"), "init"], env=env)
        if state["db_uid"]:
            for path in Path(config["data_dir"]).glob("application.sqlite3*"):
                os.chown(path, state["db_uid"], state["db_gid"])
                path.chmod(0o660)
        switch(root, release)
        run(["systemctl", "start", *reversed(args.units)])
        (root / "installed.json").write_text(
            json.dumps(
                {
                    "commit": args.commit,
                    "version": manifest["version"],
                    "sha256": args.sha256,
                    "backup": str(backup),
                },
                indent=2,
            )
        )
        (root / "installed.json").chmod(0o644)
    except BaseException:
        rollback(root, backup, args.units)
        raise
    print(
        json.dumps({"commit": args.commit, "backup": str(backup), "state": "installed; acceptance pending"})
    )


if __name__ == "__main__":
    main()
