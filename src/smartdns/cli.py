from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import time
from pathlib import Path

from cryptography.fernet import Fernet

from . import __version__
from .accounts import Accounts
from .agent_client import AgentClient
from .catalog import CatalogImporter
from .config import Settings
from .db import Database
from .security import hash_password, validate_password


def protected_output(path: str | None, data: dict) -> None:
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if path:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        print("Результат сохранён в защищённый файл")
    else:
        print(text, end="")


def main() -> None:
    parser = argparse.ArgumentParser(description="SmartDNS — управление установкой")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    cmd = sub.add_parser("migrate-alpha")
    cmd.add_argument("database")
    cmd = sub.add_parser("create")
    cmd.add_argument("login")
    cmd.add_argument("--admin", action="store_true")
    cmd.add_argument("--output")
    cmd = sub.add_parser("admin-password")
    cmd.add_argument("login")
    sub.add_parser("list")
    cmd = sub.add_parser("catalog-refresh")
    cmd.add_argument("--bootstrap", action="store_true")
    cmd = sub.add_parser("backup")
    cmd.add_argument("destination")
    args = parser.parse_args()
    settings = Settings.load()
    database = Database(settings.db_path)
    if args.command == "init":
        settings.master_key_file.parent.mkdir(parents=True, exist_ok=True)
        if not settings.master_key_file.exists():
            if settings.db_path.exists():
                raise RuntimeError(
                    "Existing database has no master key; restore the matching key from backup"
                )
            fd = os.open(settings.master_key_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(Fernet.generate_key())
        database.migrate()
        lock = settings.data_dir / "catalog-update.lock"
        if not lock.exists():
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o660)
            os.close(fd)
            if os.geteuid() == 0:
                owner = settings.data_dir.stat()
                os.chown(lock, owner.st_uid, owner.st_gid)
        with database.connect() as db:
            db.execute(
                "INSERT INTO exits(id,name,ingress_ip,egress_ip,country) VALUES(?,'Local',?,?,'XX') ON CONFLICT(id) DO UPDATE SET ingress_ip=excluded.ingress_ip,egress_ip=excluded.egress_ip,enabled=1,healthy=1,control_url=NULL",
                (settings.local_exit_id, settings.public_ipv4, settings.public_ipv4),
            )
            db.execute("UPDATE exits SET enabled=0 WHERE id!=?", (settings.local_exit_id,))
            database.bump(db)
        print("База и локальный выход подготовлены")
        return
    accounts = Accounts(settings, database)
    if args.command == "create":
        password = None
        if args.admin:
            password = getpass.getpass("Administrator password: ")
            validate_password(password)
        result = accounts.create(args.login, role="admin" if args.admin else "user")
        if password:
            with database.connect() as db:
                db.execute(
                    "UPDATE accounts SET password_hash=? WHERE id=?", (hash_password(password), result["id"])
                )
        protected_output(args.output, result)
    elif args.command == "admin-password":
        encoded = hash_password(validate_password(getpass.getpass("New administrator password: ")))
        with database.connect() as db:
            row = db.execute(
                "SELECT id FROM accounts WHERE login=? AND role='admin'", (args.login,)
            ).fetchone()
            if not row:
                raise ValueError("Administrator not found")
            db.execute("UPDATE accounts SET password_hash=? WHERE id=?", (encoded, row[0]))
            db.execute("DELETE FROM sessions WHERE account_id=?", (row[0],))
        print("Administrator password changed; sessions revoked")
    elif args.command == "migrate-alpha":
        print(json.dumps(accounts.migrate_alpha(args.database), ensure_ascii=False, indent=2))
    elif args.command == "list":
        print(json.dumps(accounts.list(), ensure_ascii=False, indent=2))
    elif args.command == "backup":
        database.backup(Path(args.destination))
        print("Согласованная резервная копия базы создана")
    elif args.command == "catalog-refresh":

        async def refresh() -> None:
            importer = CatalogImporter(database, settings.catalog_manifest)
            candidate = await importer.download()
            agent = AgentClient(settings)
            try:
                await importer.activate(candidate, agent, bootstrap=args.bootstrap)
                print(
                    json.dumps(
                        {
                            "version": candidate["version"],
                            "rules": len(candidate["rules"]),
                            "skipped": len(candidate["skipped"]),
                            "at": int(time.time()),
                        }
                    )
                )
            finally:
                await agent.close()

        asyncio.run(refresh())


if __name__ == "__main__":
    main()
