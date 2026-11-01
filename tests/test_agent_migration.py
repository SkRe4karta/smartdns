import sqlite3
import time

import pytest

from smartdns.agent import AgentEngine, HostAdapter
from smartdns.security import digest


class Adapter(HostAdapter):
    def __init__(self, root):
        super().__init__(root, enabled=False)
        self.sources = {}
        self.patterns = []
        self.fail = False

    def apply_sources(self, expiries):
        if self.fail:
            raise RuntimeError("fixture failure")
        self.sources = dict(expiries)

    def apply_patterns(self, patterns):
        self.preview(patterns)
        self.patterns = list(patterns)


@pytest.mark.asyncio
async def test_agent_acknowledges_only_active_users_and_expiring_leases(stack, tmp_path):
    adapter = Adapter(tmp_path)
    engine = AgentEngine(stack["settings"], adapter, state_dir=tmp_path / "state")
    await engine.reconcile()
    assert engine.ready()
    assert await engine.grant(stack["friend"]["id"], "8.8.8.8", "fi-primary", stack["db"].generation())
    assert "8.8.8.8" in adapter.sources
    with pytest.raises(ValueError):
        await engine.grant(stack["friend"]["id"], "127.0.0.1", "fi-primary", stack["db"].generation())
    with sqlite3.connect(engine.leases) as db:
        db.execute("UPDATE leases SET expires=0")
    await engine.reconcile()
    assert not adapter.sources
    assert await engine.grant(stack["friend"]["id"], "8.8.4.4", "fi-primary", stack["db"].generation())
    stack["accounts"].status(stack["friend"]["id"], False)
    await engine.reconcile()
    assert not adapter.sources
    assert not await engine.grant(stack["friend"]["id"], "8.8.4.4", "fi-primary", stack["db"].generation())
    await engine.http.aclose()


@pytest.mark.asyncio
async def test_agent_rotation_and_watchdog_are_fail_closed(stack, tmp_path):
    adapter = Adapter(tmp_path)
    engine = AgentEngine(stack["settings"], adapter, state_dir=tmp_path / "state")
    await engine.reconcile()
    await engine.grant(stack["owner"]["id"], "8.8.8.8", "fi-primary", stack["db"].generation())
    stack["accounts"].rotate(stack["owner"]["id"])
    await engine.reconcile()
    assert not adapter.sources
    engine.last_tick = time.monotonic() - 20
    assert not engine.ready()
    adapter.fail = True
    with pytest.raises(RuntimeError):
        await engine.reconcile()
    assert not engine.ready() and engine.last_error == "RuntimeError"
    await engine.http.aclose()


def test_agent_origin_expressions_reject_configuration_injection(tmp_path):
    adapter = Adapter(tmp_path)
    adapter.preview([r"^([a-z0-9-]+\.)*example\.com$", r"^api\.example\.com$"])
    for pattern in [".*", "^example.com$", "^example\\.com$\nbackend evil", "^(a+)+$"]:
        with pytest.raises(ValueError):
            adapter.preview([pattern])


def test_alpha_migration_is_idempotent_readonly_and_keeps_compatibility(stack, tmp_path):
    old = tmp_path / "alpha.sqlite3"
    uid = "u0123456789ab"
    token = "alpha-private-token-for-fixture"
    with sqlite3.connect(old) as db:
        db.executescript(
            "CREATE TABLE users(id TEXT,name TEXT,token_hash TEXT,enabled INTEGER,created INTEGER);CREATE TABLE networks(user_id TEXT,ip TEXT,expires INTEGER);CREATE TABLE exceptions(user_id TEXT,domain TEXT);"
        )
        db.execute("INSERT INTO users VALUES(?,?,?,?,?)", (uid, "Alpha owner", digest(token), 1, 1))
        db.execute("INSERT INTO networks VALUES(?,?,?)", (uid, "8.8.8.8", int(time.time()) + 3600))
        db.execute("INSERT INTO exceptions VALUES('*','example.com')")
    # Use an empty target for an actual first-account migration.
    with stack["db"].connect() as db:
        for table in ["sessions", "invitations", "credentials", "accounts"]:
            db.execute("DELETE FROM " + table)  # noqa: S608 -- constant table allowlist above
    original = old.read_bytes()
    first = stack["accounts"].migrate_alpha(str(old))
    second = stack["accounts"].migrate_alpha(str(old))
    assert first["imported"] == [uid] and second["imported"] == []
    assert old.read_bytes() == original
    with stack["db"].connect(readonly=True) as db:
        assert db.execute("SELECT role FROM accounts WHERE id=?", (uid,)).fetchone()[0] == "admin"
        assert (
            db.execute("SELECT ip FROM legacy_networks WHERE account_id=?", (uid,)).fetchone()[0] == "8.8.8.8"
        )
        assert (
            db.execute("SELECT domain FROM exceptions WHERE account_id=?", (uid,)).fetchone()[0]
            == "example.com"
        )
    assert stack["accounts"].authenticate(token) is None


def test_agent_is_not_ready_before_first_reconciliation_on_fresh_boot(stack, tmp_path, monkeypatch):
    engine = AgentEngine(stack["settings"], Adapter(tmp_path), state_dir=tmp_path / "state")
    monkeypatch.setattr("smartdns.agent.time.monotonic", lambda: 2.0)
    assert not engine.ready()


@pytest.mark.asyncio
async def test_reconciliation_does_not_accumulate_sqlite_descriptors(stack, tmp_path):
    import gc
    from pathlib import Path

    adapter = Adapter(tmp_path)
    engine = AgentEngine(stack["settings"], adapter, state_dir=tmp_path / "state")
    gc.collect()
    enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(80):
            await engine.reconcile()
        descriptors = []
        for path in Path("/proc/self/fd").iterdir():
            try:
                target = path.readlink()
            except FileNotFoundError:
                continue
            if str(target).startswith(str(engine.leases)):
                descriptors.append(target)
        assert len(descriptors) <= 1, f"{len(descriptors)} unclosed lease database descriptors"
    finally:
        if enabled:
            gc.enable()
        gc.collect()
        await engine.http.aclose()
