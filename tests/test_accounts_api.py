import plistlib
import time

from smartdns.catalog import CatalogImporter
from smartdns.security import digest


def test_only_admin_can_login_or_reach_connections(client, friend_client, stack):
    uid = stack["friend"]["id"]
    for path in [
        "/admin/users",
        f"/admin/users/{uid}/connection",
        f"/admin/users/{uid}/profile.mobileconfig",
        "/catalog",
    ]:
        assert friend_client.get("/api/v1" + path).status_code == 401
    assert stack["accounts"].login("friend", "friend-password-12345") is None
    assert stack["accounts"].login("owner", "owner-password-12345")
    for path in ["auth/options", "auth/invitation", "me/connection", "admin/exits"]:
        assert client.get("/api/v1/" + path).status_code == 404
    for path in ["auth/setup", "auth/telegram/start", f"admin/users/{uid}/recovery"]:
        assert client.post("/api/v1/" + path, json={}).status_code == 404


def test_username_creation_connections_filtering_rotation(client, stack):
    response = client.post("/api/v1/admin/users", json={"username": "new-friend"})
    assert response.status_code == 201
    uid = response.json()["id"]
    base = "/api/v1/admin/users/" + uid
    assert response.json()["status"] == "active" and "setup_url" not in response.json()
    assert client.post("/api/v1/admin/users", json={"username": "NEW-FRIEND"}).status_code == 409
    assert client.post("/api/v1/admin/users", json={"username": "bad user"}).status_code == 400
    assert client.post("/api/v1/admin/users", json={"username": "valid", "name": "extra"}).status_code == 422
    connection = client.get(base + "/connection").json()
    assert connection["dot"].split(".")[0] == connection["doh"].rsplit("/", 1)[1]
    profile = client.get(base + "/profile.mobileconfig")
    assert profile.headers["cache-control"] == "no-store"
    assert (
        plistlib.loads(profile.content)["PayloadContent"][0]["DNSSettings"]["ServerURL"] == connection["doh"]
    )
    assert client.put(base + "/filtering", json={"enabled": False}).status_code == 200
    assert (
        client.post(base + "/exceptions", json={"domain": "ads.example.com", "action": "block"}).status_code
        == 200
    )
    details = client.get(base).json()["user"]
    assert not details["filtering"] and details["exceptions"] == [
        {"domain": "ads.example.com", "action": "block"}
    ]
    assert client.delete(base + "/exceptions/ads.example.com").status_code == 200
    assert client.post(base + "/rotate-key").status_code == 200
    assert client.get(base + "/connection").json()["dot"] != connection["dot"]
    assert client.patch(base, json={"enabled": False}).status_code == 200
    assert client.patch(base, json={"enabled": True}).status_code == 200
    assert client.get(base).json()["user"]["status"] == "active"
    assert client.get("/api/v1/admin/users/missing/connection").status_code == 404


def test_csrf_origins_sessions_and_owner_protection(client, stack):
    base = "/api/v1/admin/users/" + stack["friend"]["id"]
    assert client.patch(base, json={"enabled": False}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert (
        client.patch(base, json={"enabled": False}, headers={"Origin": "https://evil.example"}).status_code
        == 403
    )
    assert (
        client.patch("/api/v1/admin/users/" + stack["owner"]["id"], json={"enabled": False}).status_code
        == 400
    )
    second = stack["accounts"].login("owner", "owner-password-12345")
    assert (
        client.put(
            "/api/v1/auth/password",
            json={"current": "owner-password-12345", "new": "new-admin-password-12345"},
        ).status_code
        == 200
    )
    assert stack["accounts"].authenticate(second[0]) is None
    assert stack["accounts"].authenticate(stack["owner_session"][0])


def test_migration_keeps_credentials_stats_owner_and_revokes_users(stack):
    database, accounts = stack["db"], stack["accounts"]
    uid = stack["friend"]["id"]
    before = accounts.connection(uid)
    with database.connect() as db:
        db.execute("DELETE FROM schema_migrations WHERE version=2")
        db.execute(
            "UPDATE accounts SET status='invited',password_hash='old-password',telegram_sub='old-id',filtering=0 WHERE id=?",
            (uid,),
        )
        db.execute(
            "INSERT INTO invitations VALUES(?,?,'setup',?,NULL)",
            (digest("old-invite"), uid, int(time.time()) + 60),
        )
        db.execute("INSERT INTO dns_buckets VALUES(?,?,7,2,1,0)", (uid, int(time.time())))
    database.migrate()
    database.migrate()
    assert accounts.connection(uid) == before
    assert accounts.authenticate(stack["owner_session"][0])
    assert accounts.authenticate(stack["friend_session"][0]) is None
    assert accounts.stats(uid)["totals"]["total"] == 7
    with database.connect(readonly=True) as db:
        row = db.execute("SELECT * FROM accounts WHERE id=?", (uid,)).fetchone()
        assert (
            row["status"] == "active"
            and not row["password_hash"]
            and not row["telegram_sub"]
            and not row["filtering"]
        )
        assert db.execute("SELECT COUNT(*) FROM invitations").fetchone()[0] == 0
        secret = db.execute("SELECT encrypted_secret FROM credentials WHERE account_id=?", (uid,)).fetchone()[
            0
        ]
        assert before["dot"].split(".")[0] not in secret


def test_protected_rules_are_hidden_and_cannot_be_overridden(client, stack):
    importer = CatalogImporter(stack["db"], stack["settings"].catalog_manifest)
    importer.apply(
        {
            "version": "fixture",
            "at": int(time.time()),
            "services": [{"id": "openai", "name": "AI", "category": "AI", "capability": "HTTPS"}],
            "rules": [{"domain": "chatgpt.com", "kind": "suffix", "service_id": "openai"}],
            "cidrs": [],
            "skipped": [],
        }
    )
    for path in ["catalog", "admin/catalog"]:
        data = client.get("/api/v1/" + path).text
        assert "system-adult" not in data and "pornhub" not in data
    assert client.patch("/api/v1/admin/catalog/system-adult", json={"enabled": False}).status_code == 404
    for domain in ["pornhub.com", "google.com", "connectivitycheck.gstatic.com"]:
        assert (
            client.post("/api/v1/admin/routes", json={"domain": domain, "action": "direct"}).status_code
            == 403
        )
    assert client.delete("/api/v1/admin/routes/suffix/pornhub.com").status_code == 403
    base = "/api/v1/admin/users/" + stack["friend"]["id"]
    assert (
        client.post(base + "/exceptions", json={"domain": "www.google.com", "action": "block"}).status_code
        == 400
    )
    assert (
        client.post(base + "/exceptions", json={"domain": "google.com", "action": "block"}).status_code == 200
    )
