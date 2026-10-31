from __future__ import annotations

import secrets
import sqlite3
import time
from typing import Any

from .config import Settings
from .db import Database
from .security import (
    LOGIN_RE,
    cipher,
    digest,
    hash_password,
    new_dns_key,
    new_token,
    normalize_domain,
    password_ok,
    validate_password,
)


class Accounts:
    def __init__(self, settings: Settings, db: Database):
        self.settings, self.db = settings, db
        self.crypto = cipher(settings.master_key_file)

    def _credential(self, db: sqlite3.Connection, account_id: str) -> None:
        key = new_dns_key()
        db.execute(
            "INSERT INTO credentials(account_id,secret_hash,encrypted_secret) VALUES(?,?,?)",
            (account_id, digest(key), self.crypto.encrypt(key.encode()).decode()),
        )

    def create(self, login: str, name: str, *, role: str = "user") -> dict[str, Any]:
        login = login.strip().lower()
        if not LOGIN_RE.fullmatch(login):
            raise ValueError("Логин: 3–40 латинских букв, цифр, точек, дефисов или подчёркиваний")
        if not 1 <= len(name.strip()) <= 100 or role not in ("user", "admin"):
            raise ValueError("Некорректные параметры пользователя")
        account_id, token, now = "u" + secrets.token_hex(6), new_token(), int(time.time())
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if (
                db.execute("SELECT COUNT(*) FROM accounts WHERE status!='disabled'").fetchone()[0]
                >= self.settings.user_limit
            ):
                raise ValueError("Достигнут лимит пользователей")
            db.execute(
                "INSERT INTO accounts(id,login,name,role,status,created) VALUES(?,?,?,?,'invited',?)",
                (account_id, login, name.strip(), role, now),
            )
            self._credential(db, account_id)
            db.execute(
                "INSERT INTO invitations VALUES(?,?, 'setup',?,NULL)",
                (digest(token), account_id, now + 72 * 3600),
            )
            self.db.bump(db)
        return {"id": account_id, "setup_url": f"{self.settings.public_url}/setup#{token}"}

    def invite(self, account_id: str, *, recovery: bool = False) -> str:
        token, now = new_token(), int(time.time())
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            account = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
            if not account or account["status"] == "disabled":
                raise ValueError("Доступный пользователь не найден")
            db.execute("DELETE FROM invitations WHERE account_id=?", (account_id,))
            if recovery:
                db.execute("DELETE FROM sessions WHERE account_id=?", (account_id,))
                db.execute(
                    "UPDATE accounts SET telegram_sub=NULL,password_hash=NULL WHERE id=?", (account_id,)
                )
            db.execute(
                "INSERT INTO invitations VALUES(?,?,?,?,NULL)",
                (digest(token), account_id, "recovery" if recovery else "setup", now + 72 * 3600),
            )
        return f"{self.settings.public_url}/setup#{token}"

    def invite_info(self, token: str) -> dict[str, Any] | None:
        with self.db.connect(readonly=True) as db:
            row = db.execute(
                "SELECT a.id,a.login,a.name,i.purpose FROM invitations i JOIN accounts a "
                "ON a.id=i.account_id WHERE i.token_hash=? AND i.used IS NULL AND i.expires>? "
                "AND a.status!='disabled'",
                (digest(token), int(time.time())),
            ).fetchone()
            return dict(row) if row else None

    def setup(self, token: str, password: str) -> tuple[str, str]:
        validate_password(password)
        encoded = hash_password(password)
        now = int(time.time())
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT i.*,a.status FROM invitations i JOIN accounts a ON a.id=i.account_id "
                "WHERE i.token_hash=? AND i.used IS NULL AND i.expires>? AND a.status!='disabled'",
                (digest(token), now),
            ).fetchone()
            if not row:
                raise ValueError("Ссылка недействительна или уже использована")
            db.execute("UPDATE invitations SET used=? WHERE token_hash=?", (now, digest(token)))
            db.execute("DELETE FROM sessions WHERE account_id=?", (row["account_id"],))
            db.execute(
                "UPDATE accounts SET password_hash=?,status='active' WHERE id=?", (encoded, row["account_id"])
            )
            self.db.bump(db)
            return self._session(db, row["account_id"])

    def _session(self, db: sqlite3.Connection, account_id: str) -> tuple[str, str]:
        token, csrf, now = new_token(), new_token(), int(time.time())
        db.execute("DELETE FROM sessions WHERE expires<=?", (now,))
        db.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?)",
            (digest(token), account_id, csrf, now, now + self.settings.session_days * 86400),
        )
        return token, csrf

    def login(self, login: str, password: str) -> tuple[str, str] | None:
        with self.db.connect(readonly=True) as db:
            row = db.execute(
                "SELECT * FROM accounts WHERE login=? COLLATE NOCASE", (login.strip(),)
            ).fetchone()
        encoded = row["password_hash"] if row else None
        if not password_ok(encoded, password) or not row or row["status"] != "active":
            return None
        with self.db.connect() as db:
            # Recheck after password verification: the account may have been disabled or reset.
            current = db.execute(
                "SELECT status,password_hash FROM accounts WHERE id=?", (row["id"],)
            ).fetchone()
            if not current or current["status"] != "active" or current["password_hash"] != encoded:
                return None
            return self._session(db, row["id"])

    def authenticate(self, token: str | None) -> dict[str, Any] | None:
        if not token or len(token) > 100:
            return None
        with self.db.connect(readonly=True) as db:
            row = db.execute(
                "SELECT a.*,s.csrf,s.token_hash AS session_hash FROM sessions s JOIN accounts a "
                "ON a.id=s.account_id WHERE s.token_hash=? AND s.expires>? AND a.status='active'",
                (digest(token), int(time.time())),
            ).fetchone()
            return dict(row) if row else None

    def connection(self, account_id: str) -> dict[str, Any]:
        with self.db.connect(readonly=True) as db:
            row = db.execute(
                "SELECT encrypted_secret,version FROM credentials WHERE account_id=?", (account_id,)
            ).fetchone()
            if not row:
                raise ValueError("Профиль не найден")
            key = self.crypto.decrypt(row["encrypted_secret"].encode()).decode()
        return {
            "dot": f"{key}.{self.settings.domain}",
            "doh": f"{self.settings.public_url}/dns-query/{key}",
            "bootstrap": self.settings.public_ipv4,
            "version": row["version"],
        }

    def rotate(self, account_id: str) -> None:
        key = new_dns_key()
        with self.db.connect() as db:
            db.execute(
                "UPDATE credentials SET secret_hash=?,encrypted_secret=?,version=version+1 WHERE account_id=?",
                (digest(key), self.crypto.encrypt(key.encode()).decode(), account_id),
            )
            db.execute("DELETE FROM legacy_networks WHERE account_id=?", (account_id,))
            db.execute("DELETE FROM legacy_access WHERE account_id=?", (account_id,))
            self.db.bump(db)

    def password(self, account_id: str, old: str | None, new: str, session_hash: str) -> None:
        validate_password(new)
        with self.db.connect(readonly=True) as db:
            row = db.execute("SELECT password_hash FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not row or (row["password_hash"] and not password_ok(row["password_hash"], old or "")):
            raise ValueError("Текущий пароль неверен")
        encoded = hash_password(new)
        with self.db.connect() as db:
            db.execute("UPDATE accounts SET password_hash=? WHERE id=?", (encoded, account_id))
            db.execute(
                "DELETE FROM sessions WHERE account_id=? AND token_hash!=?", (account_id, session_hash)
            )

    def status(self, account_id: str, enabled: bool) -> None:
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
            if not row:
                raise ValueError("Пользователь не найден")
            if not enabled and row["role"] == "admin":
                remaining = db.execute(
                    "SELECT COUNT(*) FROM accounts WHERE role='admin' AND status='active' AND id!=?",
                    (account_id,),
                ).fetchone()[0]
                if remaining == 0:
                    raise ValueError("Нельзя отключить последнего администратора")
            if enabled and row["status"] == "disabled":
                count = db.execute("SELECT COUNT(*) FROM accounts WHERE status!='disabled'").fetchone()[0]
                if count >= self.settings.user_limit:
                    raise ValueError("Достигнут лимит пользователей")
            new_status = (
                "active"
                if enabled and (row["password_hash"] or row["telegram_sub"])
                else "invited"
                if enabled
                else "disabled"
            )
            db.execute("UPDATE accounts SET status=? WHERE id=?", (new_status, account_id))
            if not enabled:
                db.execute("DELETE FROM sessions WHERE account_id=?", (account_id,))
                db.execute("DELETE FROM invitations WHERE account_id=?", (account_id,))
                db.execute("DELETE FROM legacy_networks WHERE account_id=?", (account_id,))
            self.db.bump(db)

    def exception(self, account_id: str, domain: str, action: str | None) -> None:
        domain = normalize_domain(domain)
        if action == "block" and (
            domain == self.settings.domain or domain.endswith("." + self.settings.domain)
        ):
            raise ValueError("Нельзя заблокировать адрес самого сервиса")
        with self.db.connect() as db:
            if action is None:
                db.execute("DELETE FROM exceptions WHERE account_id=? AND domain=?", (account_id, domain))
            elif action in ("allow", "block"):
                db.execute(
                    "INSERT INTO exceptions VALUES(?,?,?) ON CONFLICT(account_id,domain) DO UPDATE SET action=excluded.action",
                    (account_id, domain, action),
                )
            else:
                raise ValueError("Некорректное действие")
            self.db.bump(db)

    def migrate_alpha(self, alpha: str) -> dict[str, Any]:
        now, imported = int(time.time()), []
        # Read-only source. The original alpha database is never edited.
        with sqlite3.connect(f"file:{alpha}?mode=ro", uri=True) as old:
            old.row_factory = sqlite3.Row
            users = old.execute("SELECT * FROM users ORDER BY created,id").fetchall()
            nets = old.execute("SELECT * FROM networks WHERE expires>?", (now,)).fetchall()
            exceptions = old.execute("SELECT * FROM exceptions").fetchall()
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for n, user in enumerate(users):
                if db.execute("SELECT 1 FROM accounts WHERE id=?", (user["id"],)).fetchone():
                    continue
                login = "owner" if n == 0 else user["id"]
                db.execute(
                    "INSERT INTO accounts(id,login,name,role,status,created) VALUES(?,?,?,?,?,?)",
                    (
                        user["id"],
                        login,
                        user["name"],
                        "admin" if n == 0 else "user",
                        "active" if user["enabled"] else "disabled",
                        user["created"],
                    ),
                )
                self._credential(db, user["id"])
                db.execute(
                    "INSERT INTO legacy_access VALUES(?,?,?)",
                    (user["token_hash"], user["id"], now + 30 * 86400),
                )
                imported.append(user["id"])
            for net in nets:
                db.execute(
                    "INSERT OR IGNORE INTO legacy_networks VALUES(?,?,?)",
                    (net["user_id"], net["ip"], min(net["expires"], now + 30 * 86400)),
                )
            for e in exceptions:
                ids = [u["id"] for u in users] if e["user_id"] == "*" else [e["user_id"]]
                for account_id in ids:
                    db.execute(
                        "INSERT OR IGNORE INTO exceptions VALUES(?,?,'allow')",
                        (account_id, normalize_domain(e["domain"])),
                    )
            self.db.bump(db)
        return {"imported": imported, "compatibility_until": now + 30 * 86400}

    def list(self) -> list[dict[str, Any]]:
        with self.db.connect(readonly=True) as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT id,login,name,role,status,filtering,created,last_dns,telegram_sub IS NOT NULL AS telegram_linked FROM accounts ORDER BY created,id"
                )
            ]

    def stats(self, account_id: str, days: int = 1) -> dict[str, Any]:
        since = int(time.time()) - days * 86400
        with self.db.connect(readonly=True) as db:
            buckets = [
                dict(r)
                for r in db.execute(
                    "SELECT bucket AS at,total,blocked,proxied,errors FROM dns_buckets WHERE account_id=? AND bucket>=? ORDER BY bucket",
                    (account_id, since),
                )
            ]
            top = [
                dict(r)
                for r in db.execute(
                    "SELECT domain,COUNT(*) AS count FROM dns_events WHERE account_id=? AND at>=? AND result='blocked' GROUP BY domain ORDER BY count DESC LIMIT 10",
                    (account_id, max(since, int(time.time()) - 86400)),
                )
            ]
            recent = [
                dict(r)
                for r in db.execute(
                    "SELECT at,domain,qtype,result,service_id,elapsed_ms FROM dns_events WHERE account_id=? ORDER BY id DESC LIMIT 50",
                    (account_id,),
                )
            ]
        totals = {k: sum(int(b[k]) for b in buckets) for k in ("total", "blocked", "proxied", "errors")}
        return {"totals": totals, "buckets": buckets, "top_blocked": top, "recent": recent}
