"""Isolated browser-test server. Never uses production paths or credentials."""

import tempfile
from pathlib import Path

import uvicorn
from cryptography.fernet import Fernet

from zelyonka.accounts import Accounts
from zelyonka.api import create_app
from zelyonka.config import Settings
from zelyonka.db import Database


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
    with tempfile.TemporaryDirectory(prefix="zelyonka-browser-") as directory:
        root = Path(directory)
        key = root / "master.key"
        key.write_bytes(Fernet.generate_key())
        settings = Settings(
            data_dir=root / "data",
            master_key_file=key,
            telegram_file=root / "telegram.json",
            public_url="http://127.0.0.1:3018",
            frontend_dir=Path(__file__).resolve().parents[1] / "frontend/dist",
            test_mode=True,
        )
        db = Database(settings.db_path)
        db.migrate()
        accounts = Accounts(settings, db)
        owner = accounts.create("browser-admin", "Тестовый администратор", role="admin")
        accounts.setup(owner["setup_url"].split("#")[1], "browser-test-password-123")
        with db.connect() as connection:
            connection.execute(
                "INSERT INTO services(id,name,category) VALUES('openai','ChatGPT / OpenAI','ИИ')"
            )
            connection.execute("INSERT INTO domain_rules VALUES('chatgpt.com','suffix','openai','fixture')")
            connection.execute(
                "INSERT INTO exits(id,name,ingress_ip,egress_ip,country) VALUES('fi-primary','Финляндия','109.120.185.213','109.120.185.213','FI')"
            )
        uvicorn.run(create_app(settings, agent=TestAgent()), host="127.0.0.1", port=3018, access_log=False)


if __name__ == "__main__":
    main()
