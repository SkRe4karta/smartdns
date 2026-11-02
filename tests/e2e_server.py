"""Isolated browser-test server. Never uses production paths or credentials."""

import tempfile
from pathlib import Path

import uvicorn
from cryptography.fernet import Fernet

from smartdns.accounts import Accounts
from smartdns.api import create_app
from smartdns.config import Settings
from smartdns.db import Database
from smartdns.security import hash_password


class TestAgent:
    async def status(self):
        return {"ready": True, "generation": 1, "heartbeat_age": 0}

    async def reconcile(self):
        return True

    async def preview(self, patterns):
        return True

    async def close(self):
        pass


def main():
    with tempfile.TemporaryDirectory(prefix="smartdns-browser-") as directory:
        root = Path(directory)
        key = root / "master.key"
        key.write_bytes(Fernet.generate_key())
        settings = Settings(
            data_dir=root / "data",
            master_key_file=key,
            public_ipv4="203.0.113.10",
            public_url="http://127.0.0.1:3018",
            frontend_dir=Path(__file__).resolve().parents[1] / "frontend/dist",
            test_mode=True,
        )
        db = Database(settings.db_path)
        db.migrate()
        accounts = Accounts(settings, db)
        owner = accounts.create("browser-admin", "Тестовый администратор", role="admin")
        with db.connect() as connection:
            connection.execute(
                "UPDATE accounts SET password_hash=? WHERE id=?",
                (hash_password("browser-test-password-123"), owner["id"]),
            )
        with db.connect() as connection:
            connection.execute(
                "INSERT INTO services(id,name,category) VALUES('openai','ChatGPT / OpenAI','ИИ')"
            )
            connection.execute("INSERT INTO domain_rules VALUES('chatgpt.com','suffix','openai','fixture')")
            connection.execute(
                "INSERT INTO exits(id,name,ingress_ip,egress_ip,country) VALUES('primary','Local','203.0.113.10','203.0.113.10','FI')"
            )
        uvicorn.run(create_app(settings, agent=TestAgent()), host="127.0.0.1", port=3018, access_log=False)


if __name__ == "__main__":
    main()
