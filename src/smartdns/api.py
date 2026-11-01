import asyncio
import json
import os
import plistlib
import sqlite3
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .accounts import Accounts
from .agent_client import AgentClient
from .catalog import Catalog, CatalogImporter
from .config import Settings
from .db import Database
from .security import digest, equal, normalize_domain


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Body):
    login: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)


class NewUser(Body):
    username: str = Field(min_length=3, max_length=40)


class Enabled(Body):
    enabled: bool


class ExceptionRule(Body):
    domain: str = Field(max_length=253)
    action: Literal["allow", "block"]


class Password(Body):
    current: str | None = Field(default=None, max_length=256)
    new: str = Field(min_length=12, max_length=256)


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
            "PayloadIdentifier": "org.smartdns.profile." + identifier,
            "PayloadUUID": uid("profile"),
            "PayloadDisplayName": "SmartDNS",
            "PayloadRemovalDisallowed": False,
            "PayloadContent": [
                {
                    "PayloadType": "com.apple.dnsSettings.managed",
                    "PayloadVersion": 1,
                    "PayloadIdentifier": "org.smartdns.profile." + identifier + ".dns",
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
    catalog = Catalog(db, settings.domain, settings.reserved_sni)
    control = agent or AgentClient(settings)
    refresh_lock = asyncio.Lock()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        await control.close()

    app = FastAPI(
        title="SmartDNS",
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
            raise HTTPException(401, "Войди как администратор")
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
            "has_password": bool(user["password_hash"]),
            "agent": await control.status(),
            "version": __version__,
        }

    @app.get("/api/v1/me/stats")
    def statistics(user: User, days: int = 1) -> dict[str, Any]:
        if days not in (1, 7):
            raise HTTPException(400, "Период должен составлять один или семь дней")
        return accounts.stats(user["id"], days)

    @app.get("/api/v1/catalog")
    def services(user: User) -> dict[str, Any]:
        return {"services": catalog.services()}

    @app.get("/api/v1/admin/users")
    def users(user: Admin) -> dict[str, Any]:
        return {"users": accounts.list(), "limit": settings.user_limit}

    @app.post("/api/v1/admin/users", status_code=201)
    async def new_user(body: NewUser, user: Admin) -> dict[str, Any]:
        result = accounts.create(body.username)
        await control.reconcile()
        db.audit(user["id"], "user.created", result["id"])
        return result

    @app.patch("/api/v1/admin/users/{account_id}")
    async def user_status(account_id: str, body: Enabled, user: Admin) -> dict[str, Any]:
        accounts.status(account_id, body.enabled)
        await control.reconcile()
        db.audit(user["id"], "user.enabled" if body.enabled else "user.disabled", account_id)
        return {"ok": True}

    @app.post("/api/v1/admin/users/{account_id}/rotate-key")
    async def admin_rotate(account_id: str, user: Admin) -> dict[str, Any]:
        with db.connect(readonly=True) as connection:
            if not connection.execute("SELECT 1 FROM accounts WHERE id=?", (account_id,)).fetchone():
                raise HTTPException(404, "Пользователь не найден")
        accounts.rotate(account_id)
        await control.reconcile()
        db.audit(user["id"], "dns-key.rotated-by-admin", account_id)
        return {"ok": True}

    def target(account_id: str) -> dict[str, Any]:
        with db.connect(readonly=True) as connection:
            row = connection.execute(
                "SELECT id,login,role,status,filtering,last_dns FROM accounts WHERE id=?", (account_id,)
            ).fetchone()
        if not row:
            raise HTTPException(404, "Пользователь не найден")
        return dict(row)

    @app.get("/api/v1/admin/users/{account_id}")
    def user_details(account_id: str, user: Admin, days: int = 1) -> dict[str, Any]:
        if days not in (1, 7):
            raise HTTPException(400, "Период должен составлять один или семь дней")
        data = target(account_id)
        with db.connect(readonly=True) as connection:
            data["exceptions"] = [
                dict(r)
                for r in connection.execute(
                    "SELECT domain,action FROM exceptions WHERE account_id=? ORDER BY domain", (account_id,)
                )
            ]
        return {"user": data, "stats": accounts.stats(account_id, days)}

    @app.get("/api/v1/admin/users/{account_id}/connection")
    def admin_connection(account_id: str, user: Admin) -> dict[str, Any]:
        target(account_id)
        return accounts.connection(account_id)

    @app.get("/api/v1/admin/users/{account_id}/profile.mobileconfig")
    def admin_profile(account_id: str, user: Admin) -> Response:
        target(account_id)
        return Response(
            apple_profile(accounts.connection(account_id), account_id),
            media_type="application/x-apple-aspen-config",
            headers={
                "Content-Disposition": 'attachment; filename="smartdns.mobileconfig"',
                "Cache-Control": "no-store",
            },
        )

    @app.put("/api/v1/admin/users/{account_id}/filtering")
    async def admin_filtering(account_id: str, body: Enabled, user: Admin) -> dict[str, Any]:
        target(account_id)
        with db.connect() as connection:
            connection.execute("UPDATE accounts SET filtering=? WHERE id=?", (int(body.enabled), account_id))
            db.bump(connection)
        await control.reconcile()
        db.audit(user["id"], "user.filtering-changed", account_id, enabled=body.enabled)
        return {"ok": True}

    @app.post("/api/v1/admin/users/{account_id}/exceptions")
    async def admin_exception(account_id: str, body: ExceptionRule, user: Admin) -> dict[str, Any]:
        target(account_id)
        accounts.exception(account_id, body.domain, body.action)
        await control.reconcile()
        db.audit(
            user["id"], "user.exception-changed", account_id, domain=body.domain, rule_action=body.action
        )
        return {"ok": True}

    @app.delete("/api/v1/admin/users/{account_id}/exceptions/{domain}")
    async def admin_delete_exception(account_id: str, domain: str, user: Admin) -> dict[str, Any]:
        target(account_id)
        accounts.exception(account_id, domain, None)
        await control.reconcile()
        db.audit(user["id"], "user.exception-deleted", account_id, domain=domain)
        return {"ok": True}

    @app.get("/api/v1/admin/catalog")
    def admin_catalog(user: Admin) -> dict[str, Any]:
        with db.connect(readonly=True) as connection:
            hidden = {r[0] for r in connection.execute("SELECT id FROM services WHERE hidden=1")}
            meta = {
                r["key"]: json.loads(r["value"])
                for r in connection.execute("SELECT * FROM metadata WHERE key LIKE 'catalog_%'")
            }
            meta.pop("catalog_skipped", None)
            overrides = [
                dict(r)
                for r in connection.execute("SELECT * FROM route_overrides ORDER BY domain")
                if r["service_id"] not in hidden and not catalog.protected(r["domain"])
            ]
            cidrs = [
                dict(r)
                for r in connection.execute("SELECT * FROM service_cidrs ORDER BY service_id,cidr")
                if r["service_id"] not in hidden
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
        if catalog.protected_service(service_id):
            raise HTTPException(404, "Сервис не найден")
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
        if catalog.protected(domain, suffix=body.kind == "suffix") or catalog.protected_service(
            body.service_id
        ):
            raise HTTPException(403, "Системное правило защищено")
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
        if catalog.protected(normalize_domain(domain), suffix=kind == "suffix"):
            raise HTTPException(403, "Системное правило защищено")
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

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
    def missing_api(path: str) -> Response:
        raise HTTPException(404, "Не найдено")

    @app.get("/{path:path}")
    def frontend(path: str) -> Response:
        if path.startswith(("api/", "dns-query")):
            raise HTTPException(404, "Не найдено")
        root = settings.frontend_dir.resolve()
        candidate = (root / path).resolve()
        if candidate.is_relative_to(root) and candidate.is_file():
            return FileResponse(candidate)
        if (root / "index.html").is_file():
            return FileResponse(root / "index.html", headers={"Cache-Control": "no-cache"})
        return JSONResponse({"service": "SmartDNS", "version": __version__})

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
