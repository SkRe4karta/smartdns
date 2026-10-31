import concurrent.futures
import plistlib

import pytest

from zelyonka.security import digest


def test_me_never_leaks_password_or_credential(client):
    response = client.get("/api/v1/me")
    assert response.status_code == 200
    assert response.json()["role"] == "admin"
    assert not {"password_hash", "secret_hash", "encrypted_secret", "telegram_sub"} & response.json().keys()


def test_user_cannot_reach_admin_endpoints(friend_client):
    for url in ["/admin/users", "/admin/exits", "/admin/system", "/admin/catalog"]:
        assert friend_client.get("/api/v1" + url).status_code == 403
    assert (
        friend_client.post("/api/v1/admin/users", json={"login": "attacker", "name": "Attacker"}).status_code
        == 403
    )


def test_other_account_id_is_never_trusted(stack, friend_client):
    own = stack["accounts"].connection(stack["friend"]["id"])
    response = friend_client.get("/api/v1/me/connection", params={"account_id": stack["owner"]["id"]})
    assert response.status_code == 200 and response.json()["doh"] == own["doh"]
    response = friend_client.post(
        "/api/v1/me/exceptions",
        json={"domain": "example.com", "action": "allow", "account_id": stack["owner"]["id"]},
    )
    assert response.status_code == 422


def test_csrf_and_cross_origin_are_rejected(client):
    assert (
        client.put(
            "/api/v1/me/filtering", json={"enabled": False}, headers={"X-CSRF-Token": "wrong"}
        ).status_code
        == 403
    )
    assert (
        client.put(
            "/api/v1/me/filtering", json={"enabled": False}, headers={"Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert client.put("/api/v1/me/filtering", json={"enabled": False}).status_code == 200


def test_cookie_security(stack):
    from dataclasses import replace

    from fastapi.testclient import TestClient

    from zelyonka.api import create_app

    settings = replace(stack["settings"], test_mode=False)
    with TestClient(create_app(settings, agent=stack["agent"]), base_url=settings.public_url) as client:
        response = client.post(
            "/api/v1/auth/login", json={"login": "owner", "password": "owner-password-12345"}
        )
        assert response.status_code == 200
        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie


def test_invitation_expiry_reuse_and_atomic_consumption(stack):
    accounts, db = stack["accounts"], stack["db"]
    invite = accounts.create("new-friend", "New")
    token = invite["setup_url"].split("#")[1]
    assert accounts.invite_info(token)["login"] == "new-friend"

    def setup():
        try:
            accounts.setup(token, "new-test-password-123")
            return True
        except ValueError:
            return False

    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _: setup(), range(2)))
    assert results.count(True) == 1
    assert accounts.invite_info(token) is None
    expired = accounts.create("expired", "Expired")["setup_url"].split("#")[1]
    with db.connect() as connection:
        connection.execute("UPDATE invitations SET expires=0 WHERE token_hash=?", (digest(expired),))
    assert accounts.invite_info(expired) is None
    with pytest.raises(ValueError):
        accounts.setup(expired, "new-test-password-123")


def test_disabled_account_loses_session_and_dns_key(stack, client, friend_client):
    from zelyonka.gateway import Gateway

    key = stack["accounts"].connection(stack["friend"]["id"])["doh"].rsplit("/", 1)[1]
    response = client.patch("/api/v1/admin/users/" + stack["friend"]["id"], json={"enabled": False})
    assert response.status_code == 200
    assert friend_client.get("/api/v1/me").status_code == 401
    gateway = Gateway(stack["settings"], agent=stack["agent"])
    assert gateway.account(key) is None


def test_last_admin_cannot_be_disabled(stack, client):
    assert (
        client.patch("/api/v1/admin/users/" + stack["owner"]["id"], json={"enabled": False}).status_code
        == 400
    )


def test_password_change_revokes_other_sessions(stack, client):
    other = stack["accounts"].login("owner", "owner-password-12345")
    response = client.put(
        "/api/v1/auth/password", json={"current": "owner-password-12345", "new": "replacement-password-123"}
    )
    assert response.status_code == 200
    assert stack["accounts"].authenticate(other[0]) is None
    assert client.get("/api/v1/me").status_code == 200
    assert stack["accounts"].login("owner", "owner-password-12345") is None


def test_credential_encrypted_at_rest_and_rotation(stack, client):
    before = client.get("/api/v1/me/connection").json()
    raw = before["doh"].rsplit("/", 1)[1]
    with stack["db"].connect(readonly=True) as db:
        row = db.execute("SELECT * FROM credentials WHERE account_id=?", (stack["owner"]["id"],)).fetchone()
        assert raw not in row["encrypted_secret"]
        assert row["secret_hash"] == digest(raw)
    after = client.post("/api/v1/me/rotate-key").json()
    assert after["doh"] != before["doh"] and after["version"] == before["version"] + 1


def test_filter_exceptions_are_personal_and_not_routes(stack, client, friend_client):
    assert (
        friend_client.post(
            "/api/v1/me/exceptions", json={"domain": "Example.COM.", "action": "block"}
        ).status_code
        == 200
    )
    assert friend_client.get("/api/v1/me/filtering").json()["exceptions"] == [
        {"domain": "example.com", "action": "block"}
    ]
    assert client.get("/api/v1/me/filtering").json()["exceptions"] == []
    assert (
        friend_client.post(
            "/api/v1/me/exceptions", json={"domain": "dns.example.test", "action": "block"}
        ).status_code
        == 400
    )
    assert (
        friend_client.post(
            "/api/v1/me/exceptions", json={"domain": "https://evil.example/path", "action": "allow"}
        ).status_code
        == 400
    )


def test_recovery_and_profile_are_scoped(stack, client, friend_client):
    original = stack["accounts"].connection(stack["friend"]["id"])
    profile = plistlib.loads(friend_client.get("/api/v1/me/profile.mobileconfig").content)
    assert profile["PayloadContent"][0]["DNSSettings"]["ServerURL"] == original["doh"]
    response = client.post("/api/v1/admin/users/" + stack["friend"]["id"] + "/recovery")
    assert response.status_code == 200
    assert friend_client.get("/api/v1/me").status_code == 401
    token = response.json()["setup_url"].split("#")[1]
    stack["accounts"].setup(token, "recovered-password-123")
    assert stack["accounts"].connection(stack["friend"]["id"])["doh"] == original["doh"]


def test_login_errors_do_not_disclose_accounts(client):
    one = client.post("/api/v1/auth/login", json={"login": "nonexistent", "password": "not-a-password"})
    two = client.post("/api/v1/auth/login", json={"login": "owner", "password": "not-a-password"})
    assert one.status_code == two.status_code == 401
    assert one.json() == two.json()


def test_users_limit_is_transactional(stack):
    from dataclasses import replace

    from zelyonka.accounts import Accounts

    accounts = Accounts(replace(stack["settings"], user_limit=2), stack["db"])
    with pytest.raises(ValueError, match="лимит"):
        accounts.create("over-limit", "No")


def test_backup_preserves_state_without_plaintext_secrets(stack, tmp_path):
    from zelyonka.db import Database

    destination = tmp_path / "backup.sqlite3"
    stack["db"].backup(destination)
    restored = Database(destination)
    with restored.connect(readonly=True) as db:
        assert db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0] == 2
    assert b"owner-password-12345" not in destination.read_bytes()
    with pytest.raises(FileExistsError):
        stack["db"].backup(destination)


def test_request_limits_and_admin_exit_validation(client):
    assert (
        client.post(
            "/api/v1/auth/login", content=b"x" * 65537, headers={"Content-Type": "application/json"}
        ).status_code
        == 413
    )
    assert (
        client.post(
            "/api/v1/admin/exits",
            json={
                "id": "evil",
                "name": "Bad",
                "ingress_ip": "127.0.0.1",
                "egress_ip": "8.8.8.8",
                "country": "US",
            },
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/admin/exits",
            json={
                "id": "second",
                "name": "Second",
                "ingress_ip": "8.8.8.8",
                "egress_ip": "8.8.8.8",
                "country": "US",
                "control_url": "http://127.0.0.1",
            },
        ).status_code
        == 400
    )


def test_dashboard_period_query_is_parsed_as_integer(client):
    for days in (1, 7):
        response = client.get("/api/v1/me/stats", params={"days": days})
        assert response.status_code == 200 and response.json()["totals"]["total"] == 0
    assert client.get("/api/v1/me/stats?days=2").status_code == 400
