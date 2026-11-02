#!/usr/bin/env python3
"""Exercise a wheel-only installation and a real alpha migration in a fresh venv."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from release_tools import unpack


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact")
    parser.add_argument("--uv", default="uv")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="smartdns-install-check-") as directory:
        root = Path(directory)
        manifest = unpack(Path(args.artifact), root / "application", allow_dirty=args.allow_dirty)
        app = root / "application"
        venv = root / "venv"

        def run(command, **kwargs):
            return subprocess.run(
                command, check=True, capture_output=True, text=True, **kwargs
            ).stdout.strip()

        run([args.uv, "venv", "--python", "3.14.4", str(venv)])
        python = venv / "bin/python"
        run(
            [
                args.uv,
                "pip",
                "install",
                "--python",
                str(python),
                "--require-hashes",
                "-r",
                str(app / "requirements.txt"),
            ]
        )
        wheel = next((app / "wheels").glob("*.whl"))
        run([args.uv, "pip", "install", "--python", str(python), "--no-deps", str(wheel)])
        config = root / "settings.json"
        config.write_text(
            json.dumps(
                {
                    "data_dir": str(root / "data"),
                    "master_key_file": str(root / "master.key"),
                    "public_url": "https://isolated.example.test",
                    "public_ipv4": "8.8.8.8",
                    "frontend_dir": str(app / "frontend/dist"),
                }
            )
        )
        env = os.environ.copy()
        env["SMARTDNS_CONFIG"] = str(config)
        env.pop("PYTHONPATH", None)
        env.pop("CREDENTIALS_DIRECTORY", None)

        def cli(*parts):
            return run([str(venv / "bin/smartdns"), *parts], cwd=root, env=env)

        cli("init")
        alpha = root / "alpha.sqlite3"
        with sqlite3.connect(alpha) as db:
            db.executescript(
                "CREATE TABLE users(id TEXT,name TEXT,token_hash TEXT,enabled INTEGER,created INTEGER);CREATE TABLE networks(user_id TEXT,ip TEXT,expires INTEGER);CREATE TABLE exceptions(user_id TEXT,domain TEXT);"
            )
            db.execute("INSERT INTO users VALUES('u0123456789ab','Migration fixture','fixture-old-hash',1,1)")
        assert json.loads(cli("migrate-alpha", str(alpha)))["imported"] == ["u0123456789ab"]
        assert json.loads(cli("migrate-alpha", str(alpha)))["imported"] == []
        created = json.loads(cli("create", "clean-user"))
        assert created["status"] == "active" and "setup_url" not in created
        # Exercise the beta-to-admin migration in the clean installed wheel.
        with sqlite3.connect(root / "data/application.sqlite3") as db:
            db.execute("DELETE FROM schema_migrations WHERE version=2")
            before = db.execute(
                "SELECT secret_hash,encrypted_secret FROM credentials ORDER BY account_id"
            ).fetchall()
            db.execute("UPDATE accounts SET status='invited' WHERE role='user'")
        cli("init")
        with sqlite3.connect(root / "data/application.sqlite3") as db:
            assert (
                before
                == db.execute(
                    "SELECT secret_hash,encrypted_secret FROM credentials ORDER BY account_id"
                ).fetchall()
            )
            assert db.execute("SELECT COUNT(*) FROM accounts WHERE status='invited'").fetchone()[0] == 0
        cli("backup", str(root / "backup.sqlite3"))
        with sqlite3.connect(root / "backup.sqlite3") as db:
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        # Restore a real SQLite backup using the shipped rollback implementation.
        # Service management is intercepted; no host services are touched in CI.
        specification = importlib.util.spec_from_file_location("installer_check", app / "scripts/install.py")
        assert specification and specification.loader
        installer = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(installer)
        install_root, restore_dir = root / "installation", root / "restore"
        install_root.mkdir()
        restore_dir.mkdir()
        previous = install_root / "previous"
        previous.mkdir()
        shutil.copy2(root / "backup.sqlite3", restore_dir / "database.sqlite3")
        shutil.copy2(root / "master.key", restore_dir / "master.key")
        shutil.copy2(config, restore_dir / "settings.json")
        (restore_dir / "installed.json").write_text('{"commit":"previous-fixture"}')
        (install_root / "installed.json").write_text('{"commit":"candidate-fixture"}')
        units = ["fixture-api", "fixture-gateway", "fixture-agent"]
        (restore_dir / "restore.json").write_text(
            json.dumps(
                {
                    "root": str(install_root),
                    "units": units,
                    "settings": str(config),
                    "previous": str(previous),
                    "db_uid": os.getuid(),
                    "db_gid": os.getgid(),
                }
            )
        )
        with sqlite3.connect(root / "data/application.sqlite3") as db:
            db.execute("UPDATE credentials SET version=99")
        commands = []
        installer.run = lambda command, **kwargs: commands.append(command)
        installer.rollback(install_root, restore_dir, units)
        assert commands[0] == ["systemctl", "stop", *units]
        assert (install_root / "current").resolve() == previous
        assert json.loads((install_root / "installed.json").read_text())["commit"] == "previous-fixture"
        with sqlite3.connect(root / "data/application.sqlite3") as db:
            assert db.execute("SELECT MAX(version) FROM credentials").fetchone()[0] == 1
        assert (root / "master.key").read_bytes() == (restore_dir / "master.key").read_bytes()
        code = "from smartdns.config import Settings; from smartdns import __version__; import smartdns; s=Settings.load(); assert s.catalog_manifest.is_file(); print(__version__); print(smartdns.__file__)"
        installed = run([str(python), "-c", code], cwd=root, env=env)
        assert installed.splitlines()[0] == manifest["version"]
        assert str(venv) in installed
        assert (root / "master.key").stat().st_mode & 0o777 == 0o600
        print(
            json.dumps(
                {
                    "clean_install": "passed",
                    "alpha_migration": "passed",
                    "sqlite_backup_restore": "passed",
                    "commit": manifest["commit"],
                    "version": manifest["version"],
                }
            )
        )


if __name__ == "__main__":
    main()
