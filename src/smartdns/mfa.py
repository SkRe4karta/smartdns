"""RFC 6238 TOTP, encrypted enrolment and single-use recovery credentials."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
import struct
import time
from urllib.parse import quote

from .accounts import Accounts
from .security import digest, password_ok


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()  # noqa: S324 -- RFC 6238
    offset = mac[-1] & 15
    return str((struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)


class MFA:
    def __init__(self, accounts: Accounts):
        self.accounts, self.db, self.crypto = accounts, accounts.db, accounts.crypto

    def enabled(self, account_id: str) -> bool:
        with self.db.connect(readonly=True) as c:
            return bool(
                c.execute("SELECT 1 FROM totp WHERE account_id=? AND enabled=1", (account_id,)).fetchone()
            )

    def password(self, account_id: str, password: str) -> None:
        with self.db.connect(readonly=True) as c:
            row = c.execute("SELECT password_hash FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not row or not password_ok(row[0], password):
            raise ValueError("Текущий пароль неверен")

    def setup(self, account_id: str, password: str) -> dict[str, str]:
        self.password(account_id, password)
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute("SELECT 1 FROM totp WHERE account_id=? AND enabled=1", (account_id,)).fetchone():
                raise ValueError("Второй фактор уже включён")
            c.execute(
                "INSERT INTO totp VALUES(?,?,0,-1) ON CONFLICT(account_id) DO UPDATE SET secret=excluded.secret,last_step=-1",
                (account_id, self.crypto.encrypt(secret.encode()).decode()),
            )
            login = c.execute("SELECT login FROM accounts WHERE id=?", (account_id,)).fetchone()[0]
        return {
            "secret": secret,
            "uri": f"otpauth://totp/{quote('SmartDNS:' + login)}?secret={secret}&issuer=SmartDNS&digits=6&period=30",
        }

    def verify(self, c: sqlite3.Connection, account_id: str, value: str, *, pending: bool = False) -> bool:
        row = c.execute("SELECT * FROM totp WHERE account_id=?", (account_id,)).fetchone()
        if not row or (not pending and not row["enabled"]):
            return False
        if (
            not pending
            and c.execute(
                "DELETE FROM recovery_codes WHERE account_id=? AND code_hash=?",
                (account_id, digest(value.strip().replace("-", "").upper())),
            ).rowcount
        ):
            return True
        if len(value) != 6 or not value.isascii() or not value.isdigit():
            return False
        secret = self.crypto.decrypt(row["secret"].encode()).decode()
        now = int(time.time()) // 30
        for step in (now, now - 1, now + 1):
            if step > row["last_step"] and hmac.compare_digest(code_at(secret, step), value):
                c.execute("UPDATE totp SET last_step=? WHERE account_id=?", (step, account_id))
                return True
        return False

    @staticmethod
    def recovery(c: sqlite3.Connection, account_id: str) -> list[str]:
        codes = [secrets.token_hex(8).upper() for _ in range(8)]
        c.execute("DELETE FROM recovery_codes WHERE account_id=?", (account_id,))
        c.executemany("INSERT INTO recovery_codes VALUES(?,?)", [(account_id, digest(v)) for v in codes])
        return codes

    def enable(self, account_id: str, value: str, session_hash: str) -> list[str]:
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if self.enabled(account_id) or not self.verify(c, account_id, value, pending=True):
                raise ValueError("Код недействителен")
            c.execute("UPDATE totp SET enabled=1 WHERE account_id=?", (account_id,))
            c.execute("DELETE FROM sessions WHERE account_id=? AND token_hash!=?", (account_id, session_hash))
            return self.recovery(c, account_id)

    def disable(self, account_id: str, password: str, value: str) -> None:
        self.password(account_id, password)
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if not self.verify(c, account_id, value):
                raise ValueError("Код недействителен или уже использован")
            c.execute("DELETE FROM totp WHERE account_id=?", (account_id,))
            c.execute("DELETE FROM recovery_codes WHERE account_id=?", (account_id,))
            c.execute("DELETE FROM login_challenges WHERE account_id=?", (account_id,))

    def complete(self, challenge: str, value: str) -> tuple[str, str] | None:
        with self.db.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute(
                "SELECT a.id FROM login_challenges l JOIN accounts a ON a.id=l.account_id "
                "WHERE l.token_hash=? AND l.expires>? AND a.status='active' AND a.role='admin'",
                (digest(challenge), int(time.time())),
            ).fetchone()
            if not row or not self.verify(c, row[0], value):
                return None
            c.execute("DELETE FROM login_challenges WHERE token_hash=?", (digest(challenge),))
            return self.accounts._session(c, row[0])
