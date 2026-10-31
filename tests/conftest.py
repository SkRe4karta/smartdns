import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from zelyonka.accounts import Accounts
from zelyonka.api import create_app
from zelyonka.config import Settings
from zelyonka.db import Database


class FakeAgent:
    def __init__(self):
        self.ready = True
        self.grants = []

    async def grant(self, account_id, ip, exit_id, generation):
        self.grants.append((account_id, ip, exit_id, generation))
        return self.ready

    async def reconcile(self):
        return self.ready

    async def status(self):
        return {"ready": self.ready}

    async def is_ready(self, exit_id=None):
        return self.ready

    async def preview(self, patterns):
        return self.ready

    async def close(self):
        pass


@pytest.fixture
def stack(tmp_path):
    key = tmp_path / "master.key"
    key.write_bytes(Fernet.generate_key())
    settings = Settings(
        data_dir=tmp_path / "data",
        master_key_file=key,
        telegram_file=tmp_path / "telegram.json",
        public_url="https://dns.example.test",
        frontend_dir=tmp_path / "frontend",
        test_mode=True,
        agent_socket=tmp_path / "agent.sock",
    )
    database = Database(settings.db_path)
    database.migrate()
    accounts = Accounts(settings, database)
    owner = accounts.create("owner", "Owner", role="admin")
    friend = accounts.create("friend", "Friend")
    owner_session = accounts.setup(owner["setup_url"].split("#")[1], "owner-password-12345")
    friend_session = accounts.setup(friend["setup_url"].split("#")[1], "friend-password-12345")
    with database.connect() as db:
        db.execute("INSERT INTO services(id,name,category) VALUES('openai','OpenAI','AI')")
        db.execute("INSERT INTO domain_rules VALUES('chatgpt.com','suffix','openai','fixture')")
        db.execute(
            "INSERT INTO exits(id,name,ingress_ip,egress_ip,country) VALUES('fi-primary','Finland','109.120.185.213','109.120.185.213','FI')"
        )
    agent = FakeAgent()
    return {
        "settings": settings,
        "db": database,
        "accounts": accounts,
        "owner": owner,
        "friend": friend,
        "owner_session": owner_session,
        "friend_session": friend_session,
        "agent": agent,
    }


@pytest.fixture
def client(stack):
    with TestClient(
        create_app(stack["settings"], agent=stack["agent"]), base_url=stack["settings"].public_url
    ) as client:
        client.cookies.set("zd_session", stack["owner_session"][0])
        client.headers["X-CSRF-Token"] = stack["owner_session"][1]
        yield client


@pytest.fixture
def friend_client(stack):
    with TestClient(
        create_app(stack["settings"], agent=stack["agent"]), base_url=stack["settings"].public_url
    ) as client:
        client.cookies.set("zd_session", stack["friend_session"][0])
        client.headers["X-CSRF-Token"] = stack["friend_session"][1]
        yield client
