from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS accounts(
 id TEXT PRIMARY KEY,login TEXT UNIQUE NOT NULL COLLATE NOCASE,name TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','user')),
 status TEXT NOT NULL CHECK(status IN ('invited','active','disabled')),
 password_hash TEXT,telegram_sub TEXT UNIQUE,filtering INTEGER NOT NULL DEFAULT 1,
 created INTEGER NOT NULL,last_dns INTEGER);
CREATE TABLE IF NOT EXISTS credentials(
 account_id TEXT PRIMARY KEY REFERENCES accounts(id),secret_hash TEXT UNIQUE NOT NULL,
 encrypted_secret TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS invitations(
 token_hash TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),
 purpose TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),
 csrf TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_states(
 state_hash TEXT PRIMARY KEY,browser_hash TEXT NOT NULL,verifier TEXT NOT NULL,nonce TEXT NOT NULL,
 purpose TEXT NOT NULL,account_id TEXT,invite_hash TEXT,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS exceptions(
 account_id TEXT NOT NULL REFERENCES accounts(id),domain TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('allow','block')),PRIMARY KEY(account_id,domain));
CREATE TABLE IF NOT EXISTS services(
 id TEXT PRIMARY KEY,name TEXT NOT NULL,category TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,
 capability TEXT NOT NULL DEFAULT 'HTTPS',updated INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS domain_rules(
 domain TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('suffix','exact')),
 service_id TEXT NOT NULL REFERENCES services(id),source TEXT NOT NULL,
 PRIMARY KEY(domain,kind));
CREATE TABLE IF NOT EXISTS route_overrides(
 domain TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('suffix','exact')),
 action TEXT NOT NULL CHECK(action IN ('direct','proxy')),service_id TEXT REFERENCES services(id),
 PRIMARY KEY(domain,kind));
CREATE TABLE IF NOT EXISTS service_cidrs(service_id TEXT NOT NULL,cidr TEXT NOT NULL,
 source TEXT NOT NULL,PRIMARY KEY(service_id,cidr));
CREATE TABLE IF NOT EXISTS exits(
 id TEXT PRIMARY KEY,name TEXT NOT NULL,ingress_ip TEXT NOT NULL,egress_ip TEXT NOT NULL,
 country TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,healthy INTEGER NOT NULL DEFAULT 1,
 draining INTEGER NOT NULL DEFAULT 0,control_url TEXT,allowed_services TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS assignments(
 account_id TEXT NOT NULL REFERENCES accounts(id),service_id TEXT NOT NULL REFERENCES services(id),
 exit_id TEXT NOT NULL REFERENCES exits(id),created INTEGER NOT NULL,
 PRIMARY KEY(account_id,service_id));
CREATE TABLE IF NOT EXISTS legacy_access(
 token_hash TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS legacy_networks(
 account_id TEXT NOT NULL,ip TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(account_id,ip));
CREATE TABLE IF NOT EXISTS dns_events(
 id INTEGER PRIMARY KEY,account_id TEXT NOT NULL,at INTEGER NOT NULL,domain TEXT NOT NULL,
 qtype TEXT NOT NULL,result TEXT NOT NULL,service_id TEXT,exit_id TEXT,elapsed_ms REAL NOT NULL);
CREATE INDEX IF NOT EXISTS dns_events_account_time ON dns_events(account_id,at);
CREATE INDEX IF NOT EXISTS dns_events_time ON dns_events(at);
CREATE TABLE IF NOT EXISTS dns_buckets(
 account_id TEXT NOT NULL,bucket INTEGER NOT NULL,total INTEGER NOT NULL,blocked INTEGER NOT NULL,
 proxied INTEGER NOT NULL,errors INTEGER NOT NULL,PRIMARY KEY(account_id,bucket));
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY,at INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT,details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rate_limits(key TEXT PRIMARY KEY,window INTEGER NOT NULL,count INTEGER NOT NULL,expires INTEGER NOT NULL);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path

    def migrate(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='schema_migrations'").fetchone():
                version = db.execute("SELECT COALESCE(MAX(version),0) FROM schema_migrations").fetchone()[0]
                if version > 1:
                    raise ValueError("Database is newer than this application; restore the matching release")
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
            db.execute("INSERT OR IGNORE INTO schema_migrations VALUES(1,?)", (int(time.time()),))
            db.execute("INSERT OR IGNORE INTO metadata VALUES('generation','1')")

    @contextlib.contextmanager
    def connect(self, *, readonly: bool = False) -> Iterator[sqlite3.Connection]:
        name = f"file:{self.path}?mode=ro" if readonly else str(self.path)
        db = sqlite3.connect(name, uri=readonly, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            yield db
            if not readonly:
                db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def audit(self, actor: str, action: str, target: str | None = None, **details: Any) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO audit(at,actor,action,target,details) VALUES(?,?,?,?,?)",
                (int(time.time()), actor, action, target, json.dumps(details, ensure_ascii=False)),
            )

    def bump(self, db: sqlite3.Connection) -> int:
        db.execute("UPDATE metadata SET value=CAST(value AS INTEGER)+1 WHERE key='generation'")
        return int(db.execute("SELECT value FROM metadata WHERE key='generation'").fetchone()[0])

    def generation(self) -> int:
        with self.connect(readonly=True) as db:
            return int(db.execute("SELECT value FROM metadata WHERE key='generation'").fetchone()[0])

    def limited(self, key: str, count: int, seconds: int) -> bool:
        now = int(time.time())
        window = now // seconds
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO rate_limits VALUES(?,?,1,?) ON CONFLICT(key) DO UPDATE SET "
                "count=CASE WHEN window=excluded.window THEN count+1 ELSE 1 END,"
                "window=excluded.window,expires=excluded.expires",
                (key, window, (window + 1) * seconds),
            )
            n = db.execute("SELECT count FROM rate_limits WHERE key=?", (key,)).fetchone()[0]
            db.execute("DELETE FROM rate_limits WHERE expires<?", (now,))
            return int(n) > count

    def backup(self, destination: Path) -> None:
        if destination.exists():
            raise FileExistsError(destination)
        with self.connect(readonly=True) as source, sqlite3.connect(destination) as target:
            source.backup(target)
        destination.chmod(0o600)
