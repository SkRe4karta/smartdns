from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from .accounts import Accounts
from .config import Settings
from .security import digest, equal, new_token

ISSUER = "https://oauth.telegram.org"
ALGORITHMS = frozenset({"RS256", "ES256", "EdDSA", "ES256K"})


class TelegramOIDC:
    def __init__(self, settings: Settings, accounts: Accounts):
        self.settings, self.accounts = settings, accounts
        self.jwks: dict[str, Any] = {}
        self.jwks_until = 0.0

    def credentials(self) -> dict[str, str]:
        try:
            data = json.loads(self.settings.telegram_file.read_text())
        except OSError, ValueError:
            return {}
        return (
            {"client_id": str(data["client_id"]), "client_secret": str(data["client_secret"])}
            if data.get("client_id") and data.get("client_secret")
            else {}
        )

    def start(self, *, account_id: str | None, invite: str | None) -> tuple[str, str]:
        config = self.credentials()
        if not config:
            raise ValueError("Вход через Telegram пока не настроен")
        state, verifier, nonce, browser = new_token(), new_token(), new_token(), new_token()
        now = int(time.time())
        purpose = "link" if account_id else "login"
        invite_hash = None
        if invite:
            info = self.accounts.invite_info(invite)
            if not info:
                raise ValueError("Ссылка первоначальной настройки недействительна")
            purpose, account_id, invite_hash = "setup", info["id"], digest(invite)
        with self.accounts.db.connect() as db:
            db.execute("DELETE FROM oauth_states WHERE expires<=?", (now,))
            db.execute(
                "INSERT INTO oauth_states VALUES(?,?,?,?,?,?,?,?)",
                (
                    digest(state),
                    digest(browser),
                    self.accounts.crypto.encrypt(verifier.encode()).decode(),
                    nonce,
                    purpose,
                    account_id,
                    invite_hash,
                    now + 600,
                ),
            )
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        url = (
            ISSUER
            + "/auth?"
            + urlencode(
                {
                    "client_id": config["client_id"],
                    "redirect_uri": self.settings.public_url + "/api/v1/auth/telegram/callback",
                    "response_type": "code",
                    "scope": "openid profile",
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        )
        return url, browser

    async def verify(
        self, encoded: str, nonce: str, client_id: str, client: httpx.AsyncClient
    ) -> dict[str, Any]:
        header = jwt.get_unverified_header(encoded)
        algorithm, kid = header.get("alg"), header.get("kid")
        if algorithm not in ALGORITHMS or not isinstance(kid, str):
            raise ValueError("Недопустимая подпись Telegram")
        for attempt in range(2):
            if time.monotonic() >= self.jwks_until or attempt:
                response = await client.get(ISSUER + "/.well-known/jwks.json")
                response.raise_for_status()
                self.jwks = response.json()
                self.jwks_until = time.monotonic() + 3600
            keys = [key for key in self.jwks.get("keys", []) if key.get("kid") == kid]
            if keys:
                break
        if len(keys) != 1:
            raise ValueError("Ключ Telegram не найден")
        key = jwt.PyJWK.from_dict(keys[0], algorithm=algorithm)
        claims = jwt.decode(
            encoded,
            key.key,
            algorithms=[algorithm],
            issuer=ISSUER,
            audience=client_id,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
            leeway=30,
        )
        if not isinstance(claims["nonce"], str) or not equal(claims["nonce"], nonce):
            raise ValueError("Недействительный nonce")
        return claims

    async def callback(
        self, code: str, state: str, browser: str, session_token: str | None = None
    ) -> tuple[str, str]:
        now = int(time.time())
        if not code or len(code) > 4096 or not state or not browser:
            raise ValueError("Неполный ответ Telegram")
        with self.accounts.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM oauth_states WHERE state_hash=? AND browser_hash=? AND expires>?",
                (digest(state), digest(browser), now),
            ).fetchone()
            if not row:
                raise ValueError("Недействительное состояние входа")
            db.execute("DELETE FROM oauth_states WHERE state_hash=?", (digest(state),))
        if row["purpose"] == "link":
            session = self.accounts.authenticate(session_token)
            if not session or session["id"] != row["account_id"]:
                raise ValueError("Сеанс завершён; начни привязку Telegram заново")
        config = self.credentials()
        if not config:
            raise ValueError("Telegram Login не настроен")
        verifier = self.accounts.crypto.decrypt(row["verifier"].encode()).decode()
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                ISSUER + "/token",
                auth=(config["client_id"], config["client_secret"]),
                data={
                    "grant_type": "authorization_code",
                    "client_id": config["client_id"],
                    "code": code,
                    "redirect_uri": self.settings.public_url + "/api/v1/auth/telegram/callback",
                    "code_verifier": verifier,
                },
            )
            response.raise_for_status()
            claims = await self.verify(response.json()["id_token"], row["nonce"], config["client_id"], client)
        subject = str(claims["sub"])
        now = int(time.time())
        with self.accounts.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            linked = db.execute("SELECT * FROM accounts WHERE telegram_sub=?", (subject,)).fetchone()
            if row["purpose"] == "login":
                if not linked or linked["status"] != "active":
                    raise ValueError("Этот Telegram не привязан к доступному аккаунту")
                account_id = linked["id"]
            else:
                account_id = row["account_id"]
                account = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
                if not account or account["status"] == "disabled" or (linked and linked["id"] != account_id):
                    raise ValueError("Telegram уже привязан или аккаунт отключён")
                if row["purpose"] == "setup":
                    invite = db.execute(
                        "SELECT * FROM invitations WHERE token_hash=? AND account_id=? AND used IS NULL AND expires>?",
                        (row["invite_hash"], account_id, now),
                    ).fetchone()
                    if not invite:
                        raise ValueError("Приглашение истекло или использовано")
                    db.execute("UPDATE invitations SET used=? WHERE token_hash=?", (now, row["invite_hash"]))
                    db.execute("UPDATE accounts SET status='active' WHERE id=?", (account_id,))
                elif account["status"] != "active":
                    raise ValueError("Аккаунт недоступен")
                elif not db.execute(
                    "SELECT 1 FROM sessions WHERE token_hash=? AND account_id=? AND expires>?",
                    (digest(session_token or ""), account_id, now),
                ).fetchone():
                    raise ValueError("Сеанс привязки завершён")
                db.execute("UPDATE accounts SET telegram_sub=? WHERE id=?", (subject, account_id))
                self.accounts.db.bump(db)
            return self.accounts._session(db, account_id)
