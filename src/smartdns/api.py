import asyncio
import json
import os
import plistlib
import sqlite3
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal

import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .accounts import Accounts
from .agent_client import AgentClient
from .catalog import Catalog, CatalogImporter
from .config import Settings
from .db import Database
from .oidc import TelegramOIDC
from .security import digest, equal, normalize_domain, public_ipv4


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Body):
    login: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class Token(Body):
    token: str = Field(min_length=20, max_length=100)


class Setup(Token):
    password: str = Field(min_length=12, max_length=256)


class NewUser(Body):
    login: str = Field(min_length=3, max_length=40)
    name: str = Field(min_length=1, max_length=100)


class Enabled(Body):
    enabled: bool


class ExceptionRule(Body):
    domain: str = Field(max_length=253)
    action: Literal["allow", "block"]


class Password(Body):
    current: str | None = Field(default=None, max_length=256)
    new: str = Field(min_length=12, max_length=256)


class TelegramStart(Body):
    invite: str | None = Field(default=None, max_length=100)


class NewExit(Body):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    name: str = Field(min_length=1, max_length=80)
    ingress_ip: str = Field(max_length=45)
    egress_ip: str = Field(max_length=45)
    country: str = Field(pattern=r"^[A-Z]{2}$")
    control_url: str | None = Field(default=None, max_length=200)


class ExitUpdate(Body):
    enabled: bool
    draining: bool = False
    allowed_services: list[str] = Field(default_factory=list, max_length=100)


class Override(Body):
    domain: str = Field(max_length=253)
    kind: Literal["exact", "suffix"] = "suffix"
    action: Literal["direct", "proxy"]
    service_id: str | None = Field(default=None, max_length=50)


def apple_profile(connection: dict[str, Any], identifier: str) -> bytes:
    def uid(suffix: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, identifier + suffix))

    return plistlib.dumps(
        {
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": "org.smartdns.dns." + identifier,
            "PayloadUUID": uid("profile"),
            "PayloadDisplayName": "SmartDNS",
            "PayloadRemovalDisallowed": False,
            "PayloadContent": [
                {
                    "PayloadType": "com.apple.dnsSettings.managed",
                    "PayloadVersion": 1,
                    "PayloadIdentifier": "org.smartdns.dns." + identifier + ".dns",
                    "PayloadUUID": uid("dns"),
                    "PayloadDisplayName": "SmartDNS",
                    "DNSSettings": {
                        "DNSProtocol": "HTTPS",
                        "ServerURL": connection["doh"],
                        "ServerAddresses": [connection["bootstrap"]],
                    },
                }
            ],
        },
        sort_keys=False,
    )


def create_app(settings: Settings | None = None, *, agent: Any = None) -> FastAPI:
    settings = settings or Settings.load()
    db = Database(settings.db_path)
    accounts = Accounts(settings, db)
    catalog = Catalog(db, settings.domain)
    control = agent or AgentClient(settings)
    telegram = TelegramOIDC(settings, accounts)
    refresh_lock = asyncio.Lock()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        await control.close()

    app = FastAPI(
        title="SmartDNS DNS",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings, app.state.accounts, app.state.db = settings, accounts, db

    @app.middleware("http")
    async def headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        try:
            if int(request.headers.get("content-length", "0")) > 65536:
                return JSONResponse({"detail": "Запрос слишком большой"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "Некорректная длина запроса"}, status_code=400)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("origin") not in (None, settings.public_url):
                return JSONResponse({"detail": "Недопустимый источник запроса"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ValueError)
    async def invalid(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.exception_handler(sqlite3.IntegrityError)
    async def conflict(request: Request, exc: sqlite3.IntegrityError) -> JSONResponse:
        return JSONResponse(
            {"detail": "Запись уже существует или связана с другими данными"}, status_code=409
        )

    def current(request: Request) -> dict[str, Any]:
        account = accounts.authenticate(request.cookies.get("zd_session"))
        if not account:
            raise HTTPException(401, "Войди в личный кабинет")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            csrf = request.headers.get("x-csrf-token", "")
            if not equal(csrf, account["csrf"]):
                raise HTTPException(403, "Недействительный CSRF-токен")
        return account

    User = Annotated[dict[str, Any], Depends(current)]

    def admin(user: User) -> dict[str, Any]:
        if user["role"] != "admin":
            raise HTTPException(403, "Нужны права администратора")
        return user

    Admin = Annotated[dict[str, Any], Depends(admin)]

    def source(request: Request) -> str:
        peer = request.client.host if request.client else ""
        return request.headers.get("x-real-ip", "") if peer == "127.0.0.1" else peer

    def cookie(response: Response, session: tuple[str, str]) -> None:
        response.set_cookie(
            "zd_session",
            session[0],
            httponly=True,
            secure=not settings.test_mode,
            samesite="lax",
            max_age=settings.session_days * 86400,
            path="/",
        )

    def rate(request: Request, scope: str, count: int, seconds: int = 600) -> None:
        if db.limited(scope + ":" + digest(source(request)), count, seconds):
            raise HTTPException(429, "Слишком много попыток. Попробуй позже")

    @app.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        return {"version": __version__, "ready": True}

    @app.get("/api/v1/auth/options")
    async def options() -> dict[str, Any]:
        return {"telegram": bool(telegram.credentials()), "version": __version__}

    @app.post("/api/v1/auth/invitation")
    def invitation(body: Token, request: Request) -> dict[str, Any]:
        rate(request, "invite", 100)
        info = accounts.invite_info(body.token)
        if not info:
            raise HTTPException(404, "Ссылка недействительна или уже использована")
        return info

    @app.post("/api/v1/auth/setup")
    async def setup(body: Setup, request: Request, response: Response) -> dict[str, Any]:
        rate(request, "setup", 30)
        session = await asyncio.to_thread(accounts.setup, body.token, body.password)
        await control.reconcile()
        cookie(response, session)
        return {"ok": True}

    @app.post("/api/v1/auth/login")
    async def login(body: Login, request: Request, response: Response) -> dict[str, Any]:
        rate(request, "login", 100)
        if db.limited("login-user:" + digest(body.login.strip().lower()), 20, 300):
            raise HTTPException(429, "Слишком много попыток входа")
        session = await asyncio.to_thread(accounts.login, body.login, body.password)
        if not session:
            raise HTTPException(401, "Неверный логин или пароль")
        cookie(response, session)
        return {"ok": True}

    @app.post("/api/v1/auth/telegram/start")
    def telegram_start(body: TelegramStart, request: Request, response: Response) -> dict[str, Any]:
        rate(request, "telegram", 60)
        account = accounts.authenticate(request.cookies.get("zd_session"))
        if account and not equal(request.headers.get("x-csrf-token", ""), account["csrf"]):
            raise HTTPException(403, "Недействительный CSRF-токен")
        url, browser = telegram.start(account_id=account["id"] if account else None, invite=body.invite)
        response.set_cookie(
            "zd_oauth",
            browser,
            max_age=600,
            httponly=True,
            secure=not settings.test_mode,
            samesite="lax",
            path="/api/v1/auth/telegram",
        )
        return {"url": url}

    @app.get("/api/v1/auth/telegram/callback")
    async def telegram_callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
        try:
            session = await telegram.callback(
                code, state, request.cookies.get("zd_oauth", ""), request.cookies.get("zd_session")
            )
            await control.reconcile()
        except ValueError, KeyError, jwt.PyJWTError, httpx.HTTPError:
            return RedirectResponse("/login?error=telegram", status_code=303)
        response = RedirectResponse("/app", status_code=303)
        cookie(response, session)
        response.delete_cookie("zd_oauth", path="/api/v1/auth/telegram")
        return response

    @app.post("/api/v1/auth/logout")
    def logout(user: User, response: Response) -> dict[str, Any]:
        with db.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (user["session_hash"],))
        response.delete_cookie("zd_session", path="/")
        return {"ok": True}

    @app.post("/api/v1/auth/logout-others")
    def logout_others(user: User) -> dict[str, Any]:
        with db.connect() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE account_id=? AND token_hash!=?",
                (user["id"], user["session_hash"]),
            )
        return {"ok": True}

    @app.put("/api/v1/auth/password")
    async def password(body: Password, user: User) -> dict[str, Any]:
        await asyncio.to_thread(accounts.password, user["id"], body.current, body.new, user["session_hash"])
        db.audit(user["id"], "password.changed", user["id"])
        return {"ok": True}

    @app.delete("/api/v1/auth/telegram")
    def unlink(user: User) -> dict[str, Any]:
        if not user["password_hash"]:
            raise ValueError("Сначала установи пароль")
        with db.connect() as connection:
            connection.execute("UPDATE accounts SET telegram_sub=NULL WHERE id=?", (user["id"],))
        db.audit(user["id"], "telegram.unlinked", user["id"])
        return {"ok": True}

    @app.get("/api/v1/me")
    async def me(user: User) -> dict[str, Any]:
        return {
            "id": user["id"],
            "login": user["login"],
            "name": user["name"],
            "role": user["role"],
            "filtering": bool(user["filtering"]),
            "last_dns": user["last_dns"],
            "csrf": user["csrf"],
            "telegram_linked": bool(user["telegram_sub"]),
            "has_password": bool(user["password_hash"]),
            "agent": await control.status(),
            "version": __version__,
        }

    @app.get("/api/v1/me/connection")
    def connection(user: User) -> dict[str, Any]:
        return accounts.connection(user["id"])

    @app.get("/api/v1/me/profile.mobileconfig")
    def profile(user: User) -> Response:
        return Response(
            apple_profile(accounts.connection(user["id"]), user["id"]),
            media_type="application/x-apple-aspen-config",
            headers={"Content-Disposition": 'attachment; filename="smartdns-dns.mobileconfig"'},
        )

    @app.post("/api/v1/me/rotate-key")
    async def rotate(user: User) -> dict[str, Any]:
        accounts.rotate(user["id"])
        await control.reconcile()
        db.audit(user["id"], "dns-key.rotated", user["id"])
        return accounts.connection(user["id"])

    @app.get("/api/v1/me/stats")
    def statistics(user: User, days: int = 1) -> dict[str, Any]:
        if days not in (1, 7):
            raise HTTPException(400, "Период должен составлять один или семь дней")
        return accounts.stats(user["id"], days)

    @app.get("/api/v1/me/filtering")
    def filtering(user: User) -> dict[str, Any]:
        with db.connect(readonly=True) as connection:
            rules = [
                dict(r)
                for r in connection.execute(
                    "SELECT domain,action FROM exceptions WHERE account_id=? ORDER BY domain", (user["id"],)
                )
            ]
        return {"enabled": bool(user["filtering"]), "exceptions": rules}

    @app.put("/api/v1/me/filtering")
    async def update_filter(body: Enabled, user: User) -> dict[str, Any]:
        with db.connect() as connection:
            connection.execute("UPDATE accounts SET filtering=? WHERE id=?", (int(body.enabled), user["id"]))
            db.bump(connection)
        await control.reconcile()
        return {"ok": True}

    @app.post("/api/v1/me/exceptions")
    async def add_exception(body: ExceptionRule, user: User) -> dict[str, Any]:
        accounts.exception(user["id"], body.domain, body.action)
        await control.reconcile()
        return {"ok": True}

    @app.delete("/api/v1/me/exceptions/{domain}")
    async def delete_exception(domain: str, user: User) -> dict[str, Any]:
        accounts.exception(user["id"], domain, None)
        await control.reconcile()
        return {"ok": True}

    @app.get("/api/v1/catalog")
    def services(user: User) -> dict[str, Any]:
        return {"services": catalog.services()}

    @app.get("/api/v1/admin/users")
    def users(user: Admin) -> dict[str, Any]:
        return {"users": accounts.list(), "limit": settings.user_limit}

    @app.post("/api/v1/admin/users", status_code=201)
    def new_user(body: NewUser, user: Admin) -> dict[str, Any]:
        result = accounts.create(body.login, body.name)
        db.audit(user["id"], "user.created", result["id"])
        return result

    @app.patch("/api/v1/admin/users/{account_id}")
    async def user_status(account_id: str, body: Enabled, user: Admin) -> dict[str, Any]:
        accounts.status(account_id, body.enabled)
        await control.reconcile()
        db.audit(user["id"], "user.enabled" if body.enabled else "user.disabled", account_id)
        return {"ok": True}

    @app.post("/api/v1/admin/users/{account_id}/recovery")
    def recovery(account_id: str, user: Admin) -> dict[str, Any]:
        url = accounts.invite(account_id, recovery=True)
        db.audit(user["id"], "user.recovery-issued", account_id)
        return {"setup_url": url}

    @app.post("/api/v1/admin/users/{account_id}/rotate-key")
    async def admin_rotate(account_id: str, user: Admin) -> dict[str, Any]:
        with db.connect(readonly=True) as connection:
            if not connection.execute("SELECT 1 FROM accounts WHERE id=?", (account_id,)).fetchone():
                raise HTTPException(404, "Пользователь не найден")
        accounts.rotate(account_id)
        await control.reconcile()
        db.audit(user["id"], "dns-key.rotated-by-admin", account_id)
        return {"ok": True}

    @app.get("/api/v1/admin/exits")
    def exits(user: Admin) -> dict[str, Any]:
        with db.connect(readonly=True) as connection:
            rows = [dict(r) for r in connection.execute("SELECT * FROM exits ORDER BY id")]
        for row in rows:
            row["allowed_services"] = json.loads(row["allowed_services"])
        return {"exits": rows}

    @app.post("/api/v1/admin/exits", status_code=201)
    def new_exit(body: NewExit, user: Admin) -> dict[str, Any]:
        ingress, egress = public_ipv4(body.ingress_ip), public_ipv4(body.egress_ip)
        if body.control_url:
            from urllib.parse import urlparse

            parsed = urlparse(body.control_url)
            if (
                parsed.scheme != "https"
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in ("", "/")
                or public_ipv4(parsed.hostname or "") != ingress
            ):
                raise ValueError("Укажи HTTPS-адрес агента по входному IPv4, без пути, логина и параметров")
        with db.connect() as connection:
            if connection.execute("SELECT COUNT(*) FROM exits").fetchone()[0] >= 8:
                raise ValueError("В бете поддерживается до восьми выходов")
            connection.execute(
                "INSERT INTO exits(id,name,ingress_ip,egress_ip,country,enabled,healthy,control_url) VALUES(?,?,?,?,?,0,0,?)",
                (body.id, body.name, ingress, egress, body.country, body.control_url),
            )
            db.bump(connection)
        db.audit(user["id"], "exit.created", body.id)
        return {
            "ok": True,
            "message": "Выход добавлен отключённым; подключи сертификаты агента и проверь его",
        }

    @app.patch("/api/v1/admin/exits/{exit_id}")
    async def update_exit(exit_id: str, body: ExitUpdate, user: Admin) -> dict[str, Any]:
        with db.connect() as connection:
            row = connection.execute("SELECT * FROM exits WHERE id=?", (exit_id,)).fetchone()
            if not row:
                raise HTTPException(404, "Выход не найден")
            for service_id in body.allowed_services:
                if not connection.execute("SELECT 1 FROM services WHERE id=?", (service_id,)).fetchone():
                    raise ValueError("Неизвестный сервис")
            if body.enabled and not row["healthy"]:
                raise ValueError("Сначала проверь агент и фактический выходной IP")
            connection.execute(
                "UPDATE exits SET enabled=?,draining=?,allowed_services=? WHERE id=?",
                (int(body.enabled), int(body.draining), json.dumps(body.allowed_services), exit_id),
            )
            db.bump(connection)
        await control.reconcile()
        db.audit(user["id"], "exit.updated", exit_id, enabled=body.enabled, draining=body.draining)
        return {"ok": True}

    @app.post("/api/v1/admin/exits/{exit_id}/check")
    async def check_exit(exit_id: str, user: Admin) -> dict[str, Any]:
        with db.connect(readonly=True) as connection:
            row = connection.execute("SELECT * FROM exits WHERE id=?", (exit_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Выход не найден")
        try:
            status = await control.check_exit(exit_id)
        except httpx.HTTPError as exc:
            raise HTTPException(503, "Агент недоступен") from exc
        healthy = bool(
            status.get("ready") is True
            and status.get("ingress_ip") == row["ingress_ip"]
            and status.get("egress_ip") == row["egress_ip"]
        )
        with db.connect() as connection:
            connection.execute("UPDATE exits SET healthy=? WHERE id=?", (int(healthy), exit_id))
            db.bump(connection)
        db.audit(user["id"], "exit.checked", exit_id, healthy=healthy)
        return {"healthy": healthy}

    @app.get("/api/v1/admin/catalog")
    def admin_catalog(user: Admin) -> dict[str, Any]:
        with db.connect(readonly=True) as connection:
            meta = {
                r["key"]: json.loads(r["value"])
                for r in connection.execute("SELECT * FROM metadata WHERE key LIKE 'catalog_%'")
            }
            overrides = [dict(r) for r in connection.execute("SELECT * FROM route_overrides ORDER BY domain")]
            cidrs = [
                dict(r) for r in connection.execute("SELECT * FROM service_cidrs ORDER BY service_id,cidr")
            ]
        return {
            "services": catalog.services(),
            "metadata": meta,
            "overrides": overrides,
            "cidrs": cidrs,
            "refreshing": refresh_lock.locked(),
        }

    @app.patch("/api/v1/admin/catalog/{service_id}")
    async def catalog_status(service_id: str, body: Enabled, user: Admin) -> dict[str, Any]:
        if refresh_lock.locked():
            raise HTTPException(409, "Каталог обновляется")
        with db.connect() as connection:
            if not connection.execute(
                "UPDATE services SET enabled=? WHERE id=?", (int(body.enabled), service_id)
            ).rowcount:
                raise HTTPException(404, "Сервис не найден")
            db.bump(connection)
        await control.reconcile()
        db.audit(user["id"], "catalog.service-changed", service_id, enabled=body.enabled)
        return {"ok": True}

    @app.post("/api/v1/admin/routes")
    async def route(body: Override, user: Admin) -> dict[str, Any]:
        domain = normalize_domain(body.domain)
        if body.action == "proxy" and (domain == settings.domain or domain.endswith("." + settings.domain)):
            raise ValueError("Нельзя направить адрес сервиса на самого себя")
        if refresh_lock.locked():
            raise HTTPException(409, "Каталог обновляется")
        with db.connect() as connection:
            if (
                body.action == "proxy"
                and not connection.execute("SELECT 1 FROM services WHERE id=?", (body.service_id,)).fetchone()
            ):
                raise ValueError("Для проксирования выбери сервис")
            connection.execute(
                "INSERT INTO route_overrides VALUES(?,?,?,?) ON CONFLICT(domain,kind) DO UPDATE SET action=excluded.action,service_id=excluded.service_id",
                (domain, body.kind, body.action, body.service_id),
            )
            db.bump(connection)
        await control.reconcile()
        db.audit(user["id"], "route.updated", domain, route_action=body.action)
        return {"ok": True}

    @app.delete("/api/v1/admin/routes/{kind}/{domain}")
    async def delete_route(kind: Literal["exact", "suffix"], domain: str, user: Admin) -> dict[str, Any]:
        with db.connect() as connection:
            connection.execute(
                "DELETE FROM route_overrides WHERE kind=? AND domain=?", (kind, normalize_domain(domain))
            )
            db.bump(connection)
        await control.reconcile()
        db.audit(user["id"], "route.deleted", domain)
        return {"ok": True}

    @app.post("/api/v1/admin/catalog-refresh")
    async def refresh(user: Admin) -> dict[str, Any]:
        if refresh_lock.locked():
            raise HTTPException(409, "Каталог уже обновляется")
        async with refresh_lock:
            importer = CatalogImporter(db, settings.catalog_manifest)
            candidate = await importer.download()
            await importer.activate(candidate, control)
            db.audit(user["id"], "catalog.refreshed", candidate["version"], rules=len(candidate["rules"]))
            return {
                "version": candidate["version"],
                "rules": len(candidate["rules"]),
                "skipped": len(candidate["skipped"]),
            }

    @app.get("/api/v1/admin/system")
    async def system(user: Admin) -> dict[str, Any]:
        memory = {}
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith(("MemTotal:", "MemAvailable:")):
                    name, value, *_ = line.split()
                    memory[name.rstrip(":")] = int(value) * 1024
        except OSError:
            pass
        from cryptography import x509

        expires = None
        try:
            cert = x509.load_pem_x509_certificate(settings.cert_file.read_bytes())
            expires = int(cert.not_valid_after_utc.timestamp())
        except OSError, ValueError:
            pass
        with db.connect(readonly=True) as connection:
            counts = {
                "users": connection.execute(
                    "SELECT COUNT(*) FROM accounts WHERE status!='disabled'"
                ).fetchone()[0],
                "domains": connection.execute("SELECT COUNT(*) FROM domain_rules").fetchone()[0],
            }
            audit = [
                dict(r)
                for r in connection.execute(
                    "SELECT at,actor,action,target,details FROM audit ORDER BY id DESC LIMIT 100"
                )
            ]
        return {
            "version": __version__,
            "agent": await control.status(),
            "memory": memory,
            "load": list(os.getloadavg()),
            "certificate_expires": expires,
            "counts": counts,
            "audit": audit,
        }

    # Compatibility endpoints accept only an old alpha capability for its original account.
    def legacy(request: Request) -> dict[str, Any]:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(403, "Личная ссылка недействительна")
        with db.connect(readonly=True) as connection:
            row = connection.execute(
                "SELECT a.* FROM legacy_access l JOIN accounts a ON a.id=l.account_id WHERE l.token_hash=? AND l.expires>? AND a.status='active'",
                (digest(auth[7:]), int(time.time())),
            ).fetchone()
        if not row:
            raise HTTPException(403, "Срок старой ссылки истёк или доступ отключён")
        return dict(row)

    @app.get("/api/status")
    def legacy_status(request: Request) -> dict[str, Any]:
        user = legacy(request)
        with db.connect(readonly=True) as connection:
            networks = [
                dict(r)
                for r in connection.execute(
                    "SELECT ip,expires FROM legacy_networks WHERE account_id=? AND expires>?",
                    (user["id"], int(time.time())),
                )
            ]
        return {
            "name": user["name"],
            "dot": f"{user['id']}.{settings.domain}",
            "doh": f"{settings.public_url}/dns-query/{user['id']}",
            "networks": networks,
        }

    @app.post("/api/activate")
    async def legacy_activate(request: Request) -> dict[str, Any]:
        user = legacy(request)
        rate(request, "legacy-activate", 30)
        ip = public_ipv4(source(request))
        with db.connect() as connection:
            limit = connection.execute(
                "SELECT MAX(expires) FROM legacy_access WHERE account_id=?", (user["id"],)
            ).fetchone()[0]
            expires = min(int(time.time()) + 7 * 86400, limit)
            connection.execute(
                "INSERT INTO legacy_networks VALUES(?,?,?) ON CONFLICT(account_id,ip) DO UPDATE SET expires=excluded.expires",
                (user["id"], ip, expires),
            )
            db.bump(connection)
        await control.reconcile()
        return {"ip": ip, "expires": expires}

    @app.post("/api/profile")
    def legacy_profile(request: Request) -> Response:
        user = legacy(request)
        return Response(
            apple_profile(
                {"doh": f"{settings.public_url}/dns-query/{user['id']}", "bootstrap": settings.public_ipv4},
                user["id"],
            ),
            media_type="application/x-apple-aspen-config",
        )

    @app.get("/connect")
    def legacy_page() -> FileResponse:
        return FileResponse(settings.legacy_dir / "portal.html", headers={"Cache-Control": "no-store"})

    @app.get("/{path:path}")
    def frontend(path: str) -> Response:
        if path.startswith(("api/", "dns-query")):
            raise HTTPException(404, "Не найдено")
        if path in ("app.js", "app.css") and (settings.legacy_dir / path).is_file():
            return FileResponse(settings.legacy_dir / path, headers={"Cache-Control": "no-store"})
        root = settings.frontend_dir.resolve()
        candidate = (root / path).resolve()
        if candidate.is_relative_to(root) and candidate.is_file():
            return FileResponse(candidate)
        if (root / "index.html").is_file():
            return FileResponse(root / "index.html", headers={"Cache-Control": "no-cache"})
        return JSONResponse({"service": "SmartDNS DNS", "version": __version__})

    return app


def main() -> None:
    import uvicorn

    settings = Settings.load()
    uvicorn.run(
        create_app(settings),
        host="127.0.0.1",
        port=settings.api_port,
        access_log=False,
        log_level="warning",
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
