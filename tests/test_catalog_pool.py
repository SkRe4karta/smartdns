import pytest

from smartdns.catalog import Catalog, CatalogImporter, ExitPool, parse_source
from smartdns.policy import CONNECTIVITY_NAMES, SYSTEM_SERVICE


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
    catalog = Catalog(stack["db"], stack["settings"].domain, ("dl.google.com",))
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


@pytest.mark.asyncio
async def test_failed_activation_restores_catalog_and_leaves_accounts_intact(stack, tmp_path):
    import time

    importer = CatalogImporter(stack["db"], stack["settings"].catalog_manifest)
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


def test_system_policy_is_protected_and_connectivity_is_exact(stack):
    import time

    importer = CatalogImporter(stack["db"], stack["settings"].catalog_manifest)
    importer.apply(
        {
            "version": "fixture",
            "at": int(time.time()),
            "services": [{"id": "openai", "name": "AI", "category": "AI", "capability": "HTTPS"}],
            "rules": [{"domain": "google.com", "kind": "suffix", "service_id": "openai"}],
            "cidrs": [],
            "skipped": [],
        }
    )
    cat = Catalog(stack["db"], stack["settings"].domain)
    for name in CONNECTIVITY_NAMES:
        assert cat.match(name) is None
    assert cat.match("api.google.com") == "openai"
    assert cat.match("pornhub.com") == SYSTEM_SERVICE
    assert not any(s["id"] == SYSTEM_SERVICE for s in cat.services())
    assert cat.protected("pornhub.com") and cat.protected("com", suffix=True)
    assert cat.protected("google.com", suffix=True)
    assert not cat.protected("api.google.com")
    with stack["db"].connect() as db:
        db.execute("INSERT INTO route_overrides VALUES('pornhub.com','suffix','direct',NULL)")
        stack["db"].bump(db)
    assert cat.match("www.pornhub.com") == SYSTEM_SERVICE
    assert ExitPool(stack["db"], "primary").choose(stack["owner"]["id"], "openai")["id"] == "primary"
