import time

from smartdns.catalog import Catalog, CatalogImporter


def test_rename_preserves_key_and_rejects_duplicates(client, stack):
    account_id = stack["friend"]["id"]
    before = stack["accounts"].connection(account_id)
    assert client.put(f"/api/v1/admin/users/{account_id}", json={"username": "new-name"}).status_code == 200
    assert stack["accounts"].connection(account_id) == before
    assert client.get(f"/api/v1/admin/users/{account_id}").json()["user"]["login"] == "new-name"
    assert client.put(f"/api/v1/admin/users/{account_id}", json={"username": "owner"}).status_code == 409
    assert client.put(f"/api/v1/admin/users/{account_id}", json={"username": "bad name"}).status_code == 400


def test_delete_protected_and_authorized(client, friend_client, stack):
    account_id = stack["friend"]["id"]
    endpoint = f"/api/v1/admin/users/{account_id}"
    assert friend_client.delete(endpoint).status_code == 401
    assert client.delete(f"/api/v1/admin/users/{stack['owner']['id']}").status_code == 400
    csrf = client.headers.pop("X-CSRF-Token")
    assert client.delete(endpoint).status_code == 403
    client.headers["X-CSRF-Token"] = csrf
    stack["accounts"].exception(account_id, "ads.example.test", "block")
    assert client.delete(endpoint).status_code == 200
    assert client.get(endpoint).status_code == 404
    from smartdns.telemetry import Recorder

    Recorder(stack["db"]).flush(
        [
            dict(
                account_id=account_id,
                at=int(time.time()),
                domain="example.test",
                qtype="A",
                result="allowed",
                service_id=None,
                exit_id=None,
                elapsed_ms=1,
                client_ip="203.0.113.20",
                transport="dot",
                key_version=1,
                rcode="NOERROR",
                reason=None,
            )
        ]
    )
    with stack["db"].connect(readonly=True) as db:
        assert (
            db.execute("SELECT COUNT(*) FROM dns_events WHERE account_id=?", (account_id,)).fetchone()[0] == 0
        )
        assert (
            db.execute("SELECT COUNT(*) FROM network_buckets WHERE account_id=?", (account_id,)).fetchone()[0]
            == 0
        )
    assert client.delete(endpoint).status_code == 404
    with stack["db"].connect(readonly=True) as db:
        assert (
            db.execute("SELECT COUNT(*) FROM credentials WHERE account_id=?", (account_id,)).fetchone()[0]
            == 0
        )
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []
    assert stack["accounts"].create("friend")["id"] != account_id


def test_gemini_additions_survive_reimport(stack):
    importer = CatalogImporter(stack["db"], stack["settings"].catalog_manifest)
    candidate = {
        "version": "fixture",
        "at": int(time.time()),
        "services": [{"id": "gemini", "name": "Gemini", "category": "AI", "capability": "HTTPS"}],
        "rules": [{"domain": "gemini.google.com", "kind": "suffix", "service_id": "gemini"}],
        "cidrs": [],
        "skipped": [],
    }
    for _ in range(2):
        importer.apply(candidate)
        catalog = Catalog(stack["db"], stack["settings"].domain)
        assert catalog.match("robinfrontend-pa.googleapis.com") == "gemini"
        assert catalog.match("geminiweb-pa.clients6.google.com") == "gemini"
        assert catalog.match("evilrobinfrontend-pa.googleapis.com") is None
        assert catalog.match("connectivitycheck.gstatic.com") is None
        assert catalog.match("www.google-analytics.com") is None
