import pytest

from zelyonka.catalog import Catalog, CatalogImporter, ExitPool, parse_source


def test_catalog_import_handles_includes_and_rejects_cycles():
    sources = {"one": "include:two\nfull:api.example.com\nregexp:.*unsafe\n", "two": "example.com\n"}
    rows, skipped = parse_source("one", sources)
    assert rows == {("example.com", "suffix"), ("api.example.com", "exact")}
    assert len(skipped) == 1
    with pytest.raises(ValueError):
        parse_source("one", {"one": "include:two", "two": "include:one"})
    with pytest.raises(ValueError):
        parse_source("one", {"one": "include:missing"})


def test_suffix_boundaries_and_protected_infrastructure(stack):
    catalog = Catalog(stack["db"], stack["settings"].domain)
    assert catalog.match("chatgpt.com") == "openai"
    assert catalog.match("sub.chatgpt.com") == "openai"
    assert catalog.match("evilchatgpt.com") is None
    assert catalog.match("unknown.example") is None
    with stack["db"].connect() as db:
        db.execute("INSERT INTO domain_rules VALUES('google.com','suffix','openai','fixture')")
        stack["db"].bump(db)
    assert catalog.match("dl.google.com") is None


def test_manual_direct_override_beats_more_specific_import(stack):
    with stack["db"].connect() as db:
        db.execute("INSERT INTO domain_rules VALUES('specific.chatgpt.com','exact','openai','fixture')")
        db.execute("INSERT INTO route_overrides VALUES('chatgpt.com','suffix','direct',NULL)")
        stack["db"].bump(db)
    assert Catalog(stack["db"], stack["settings"].domain).match("specific.chatgpt.com") is None


def test_bad_update_preserves_last_working_rules(stack, tmp_path):
    importer = CatalogImporter(stack["db"], tmp_path / "unused")
    with pytest.raises(ValueError):
        importer.apply(
            {
                "rules": [{"domain": "example.com\nmalicious", "kind": "suffix", "service_id": "openai"}],
                "services": [{"id": "openai"}],
            }
        )
    assert Catalog(stack["db"], stack["settings"].domain).match("chatgpt.com") == "openai"


def test_pool_assignment_is_sticky_and_fails_over(stack):
    db = stack["db"]
    pool = ExitPool(db)
    uid = stack["owner"]["id"]
    first = pool.choose(uid, "openai")
    assert first["id"] == "fi-primary"
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO exits(id,name,ingress_ip,egress_ip,country) VALUES('second','Other','8.8.8.8','8.8.8.8','FI')"
        )
    assert pool.choose(uid, "openai")["id"] == "fi-primary"
    with db.connect() as conn:
        conn.execute("UPDATE exits SET healthy=0 WHERE id='fi-primary'")
    assert pool.choose(uid, "openai")["id"] == "second"
    with db.connect() as conn:
        conn.execute("UPDATE exits SET enabled=0")
    assert pool.choose(uid, "openai") is None


def test_draining_keeps_old_assignments_and_service_restrictions(stack):
    pool = ExitPool(stack["db"])
    uid = stack["owner"]["id"]
    assert pool.choose(uid, "openai")
    with stack["db"].connect() as db:
        db.execute("UPDATE exits SET draining=1")
    assert pool.choose(uid, "openai") is not None
    assert pool.choose(stack["friend"]["id"], "openai") is None
    with stack["db"].connect() as db:
        db.execute("UPDATE exits SET allowed_services='[\"different\"]'")
    assert pool.choose(uid, "openai") is None


@pytest.mark.asyncio
async def test_failed_activation_restores_catalog_and_leaves_accounts_intact(stack, tmp_path):
    import time

    importer = CatalogImporter(stack["db"], tmp_path / "unused")
    candidate = {
        "version": "new-fixture",
        "at": int(time.time()),
        "services": [{"id": "openai", "name": "Changed", "category": "AI", "capability": "HTTPS"}],
        "rules": [{"domain": "replacement.example", "kind": "suffix", "service_id": "openai"}],
        "cidrs": [],
        "skipped": [],
    }

    class FailingAgent:
        async def status(self):
            return {"ready": True}

        async def preview(self, patterns):
            return True

        async def reconcile(self):
            return False

    with pytest.raises(ValueError, match="восстановлен"):
        await importer.activate(candidate, FailingAgent())
    assert Catalog(stack["db"], stack["settings"].domain).match("chatgpt.com") == "openai"
    assert stack["accounts"].authenticate(stack["owner_session"][0])
    assert stack["accounts"].connection(stack["friend"]["id"])["doh"]
