#!/usr/bin/env python3
"""Exercise a wheel-only installation and a real alpha migration in a fresh venv."""

from __future__ import annotations

import argparse
import json
import os
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
                    "telegram_file": str(root / "telegram.json"),
                    "public_url": "https://isolated.example.test",
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
        cli("invite", "u0123456789ab", "--recovery", "--output", str(root / "invitation.json"))
        assert "/setup#" in json.loads((root / "invitation.json").read_text())["setup_url"]
        cli("backup", str(root / "backup.sqlite3"))
        with sqlite3.connect(root / "backup.sqlite3") as db:
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
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
                    "sqlite_backup": "passed",
                    "commit": manifest["commit"],
                    "version": manifest["version"],
                }
            )
        )


if __name__ == "__main__":
    main()
