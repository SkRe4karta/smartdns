from __future__ import annotations

import fcntl
import io
import ipaddress
import json
import re
import tarfile
import time
from pathlib import Path
from typing import Any

import httpx

from .db import Database
from .policy import CONNECTIVITY_NAMES, SYSTEM_SERVICE
from .security import normalize_domain

PROTECTED_NAMES = CONNECTIVITY_NAMES


class Catalog:
    def __init__(self, db: Database, own_domain: str, reserved_sni: tuple[str, ...] = ()):
        self.reserved = frozenset(reserved_sni)
        self.db, self.own_domain = db, own_domain
        self.generation = -1
        self.exact: dict[str, str | None] = {}
        self.suffix: dict[str, str | None] = {}
        self.system_exact: set[str] = set()
        self.system_suffix: set[str] = set()
        self.overrides_exact: dict[str, str | None] = {}
        self.overrides_suffix: dict[str, str | None] = {}

    def reload(self) -> None:
        generation = self.db.generation()
        if generation == self.generation:
            return
        with self.db.connect(readonly=True) as db:
            rows = db.execute(
                "SELECT d.domain,d.kind,d.service_id,s.enabled,s.protected FROM domain_rules d JOIN services s ON s.id=d.service_id"
            ).fetchall()
            overrides = db.execute("SELECT * FROM route_overrides").fetchall()
        exact: dict[str, str | None] = {}
        suffix: dict[str, str | None] = {}
        overrides_exact: dict[str, str | None] = {}
        overrides_suffix: dict[str, str | None] = {}
        self.system_exact, self.system_suffix = set(), set()
        for row in rows:
            if row["protected"]:
                (self.system_exact if row["kind"] == "exact" else self.system_suffix).add(row["domain"])
            (exact if row["kind"] == "exact" else suffix)[row["domain"]] = (
                row["service_id"] if row["enabled"] else None
            )
        for row in overrides:
            (overrides_exact if row["kind"] == "exact" else overrides_suffix)[row["domain"]] = (
                row["service_id"] if row["action"] == "proxy" else None
            )
        self.overrides_exact, self.overrides_suffix = overrides_exact, overrides_suffix
        self.exact, self.suffix, self.generation = exact, suffix, generation

    def match(self, domain: str) -> str | None:
        self.reload()
        name = domain.rstrip(".").lower()
        if (
            name in PROTECTED_NAMES
            or name in self.reserved
            or name == self.own_domain
            or name.endswith("." + self.own_domain)
        ):
            return None
        if self.system_match(name):
            return SYSTEM_SERVICE
        if name in self.overrides_exact:
            return self.overrides_exact[name]
        parts = name.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.overrides_suffix:
                return self.overrides_suffix[candidate]
        if name in self.exact:
            return self.exact[name]
        parts = name.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.suffix:
                return self.suffix[candidate]
        return None

    def system_match(self, name: str) -> bool:
        return name in self.system_exact or any(
            name == d or name.endswith("." + d) for d in self.system_suffix
        )

    def protected(self, domain: str, *, suffix: bool = False) -> bool:
        self.reload()
        if domain in PROTECTED_NAMES or self.system_match(domain):
            return True
        return suffix and any(
            d.endswith("." + domain) for d in PROTECTED_NAMES | self.system_exact | self.system_suffix
        )

    def protected_service(self, service_id: str | None) -> bool:
        with self.db.connect(readonly=True) as db:
            return bool(
                db.execute("SELECT 1 FROM services WHERE id=? AND protected=1", (service_id,)).fetchone()
            )

    def services(self) -> list[dict[str, Any]]:
        with self.db.connect(readonly=True) as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT s.*,COUNT(d.domain) AS domains FROM services s LEFT JOIN domain_rules d ON d.service_id=s.id WHERE s.hidden=0 GROUP BY s.id ORDER BY s.category,s.name"
                )
            ]

    def proxy_patterns(self) -> list[str]:
        self.reload()
        exact = self.exact | self.overrides_exact | dict.fromkeys(self.system_exact, SYSTEM_SERVICE)
        suffix = self.suffix | self.overrides_suffix | dict.fromkeys(self.system_suffix, SYSTEM_SERVICE)
        patterns = [
            "^" + re.escape(d) + "$" for d, service in exact.items() if service and d not in PROTECTED_NAMES
        ]
        patterns += [r"^([a-z0-9-]+\.)*" + re.escape(d) + "$" for d, service in suffix.items() if service]
        return sorted(set(patterns))


def parse_source(
    name: str, sources: dict[str, str], stack: tuple[str, ...] = ()
) -> tuple[set[tuple[str, str]], list[str]]:
    if name in stack or len(stack) > 20:
        raise ValueError("Catalog include cycle or excessive nesting")
    if name not in sources:
        raise ValueError(f"Missing catalog source: {name}")
    entries: set[tuple[str, str]] = set()
    skipped = []
    for line in sources[name].splitlines():
        line = line.split("#", 1)[0].strip().split(" @", 1)[0]
        if not line:
            continue
        if line.startswith("include:"):
            # Source attributes select subsets. Preserve a safe superset of domain entries.
            include = line[8:].split(" @", 1)[0].strip()
            child, omitted = parse_source(include, sources, (*stack, name))
            entries.update(child)
            skipped.extend(omitted)
        elif line.startswith(("regexp:", "keyword:")):
            skipped.append(line)
        else:
            kind = "exact" if line.startswith("full:") else "suffix"
            value = line.split(":", 1)[1] if line.startswith(("full:", "domain:")) else line
            # Other rule syntaxes never reach the generated proxy configuration.
            try:
                entries.add((normalize_domain(value), kind))
            except ValueError:
                skipped.append(line)
    return entries, skipped


class CatalogImporter:
    def __init__(self, db: Database, manifest: Path):
        self.db, self.manifest = db, manifest

    async def activate(self, candidate: dict[str, Any], control: Any, *, bootstrap: bool = False) -> int:
        # One filesystem lock covers the API and the daily CLI updater.
        with (self.db.path.parent / "catalog-update.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("Каталог уже обновляется") from exc
            with self.db.connect(readonly=True) as db:
                before_services = [tuple(r) for r in db.execute("SELECT * FROM services")]
                before_rules = [tuple(r) for r in db.execute("SELECT * FROM domain_rules")]
                before_cidrs = [tuple(r) for r in db.execute("SELECT * FROM service_cidrs")]
                before_meta = [
                    tuple(r) for r in db.execute("SELECT * FROM metadata WHERE key LIKE 'catalog_%'")
                ]
            if bootstrap and before_rules:
                raise ValueError("Первичный импорт разрешён только в пустой каталог")
            status = await control.status()
            if not status.get("ready") and not bootstrap:
                raise ValueError("Агент недоступен; рабочий каталог сохранён")
            patterns = [
                "^" + (r"([a-z0-9-]+\.)*" if r["kind"] == "suffix" else "") + re.escape(r["domain"]) + "$"
                for r in candidate["rules"]
            ]
            if status.get("ready") and not await control.preview(patterns):
                raise ValueError("Конфигурация отклонена; рабочий каталог сохранён")
            generation = self.apply(candidate)
            if bootstrap or await control.reconcile():
                return generation
            with self.db.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("DELETE FROM domain_rules")
                old_ids = {row[0] for row in before_services}
                new_ids = {r[0] for r in db.execute("SELECT id FROM services")} - old_ids
                for service_id in new_ids:
                    db.execute("DELETE FROM assignments WHERE service_id=?", (service_id,))
                    db.execute("DELETE FROM services WHERE id=?", (service_id,))
                for row in before_services:
                    db.execute(
                        "UPDATE services SET name=?,category=?,enabled=?,capability=?,updated=?,hidden=?,protected=? WHERE id=?",
                        (*row[1:], row[0]),
                    )
                db.executemany("INSERT INTO domain_rules VALUES(?,?,?,?)", before_rules)
                db.execute("DELETE FROM service_cidrs")
                db.executemany("INSERT INTO service_cidrs VALUES(?,?,?)", before_cidrs)
                db.execute("DELETE FROM metadata WHERE key LIKE 'catalog_%'")
                db.executemany("INSERT INTO metadata VALUES(?,?)", before_meta)
                self.db.bump(db)
            await control.reconcile()
            raise ValueError("Применение не удалось; предыдущий каталог восстановлен")

    async def download(self) -> dict[str, Any]:
        async with httpx.AsyncClient(
            timeout=45, follow_redirects=True, headers={"User-Agent": "SmartDNSDNS/0.2"}
        ) as client:
            response = await client.get(
                "https://api.github.com/repos/v2fly/domain-list-community/commits/master"
            )
            response.raise_for_status()
            commit = response.json()["sha"]
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ValueError("Invalid upstream commit")
            response = await client.get(
                f"https://codeload.github.com/v2fly/domain-list-community/tar.gz/{commit}"
            )
            response.raise_for_status()
            if len(response.content) > 25_000_000:
                raise ValueError("Catalog archive is too large")
            sources = {}
            with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as archive:
                for entry in archive:
                    pieces = entry.name.split("/")
                    if entry.isfile() and len(pieces) == 3 and pieces[1] == "data":
                        f = archive.extractfile(entry)
                        if f and entry.size <= 2_000_000:
                            sources[pieces[2]] = f.read().decode()
            cidr = await client.get("https://core.telegram.org/resources/cidr.txt")
            cidr.raise_for_status()
        networks = sorted(
            {
                str(ipaddress.ip_network(line.strip(), strict=True))
                for line in cidr.text.splitlines()
                if line.strip()
            }
        )
        if not networks or len(networks) > 1000:
            raise ValueError("Invalid Telegram network list")
        services = json.loads(self.manifest.read_text())
        rules: dict[tuple[str, str], str] = {}
        skipped: list[dict[str, str]] = []
        for service in services:
            entries, omitted = parse_source(service["source"], sources)
            if not entries:
                raise ValueError(f"Empty service: {service['id']}")
            for domain, kind in sorted(entries):
                if domain not in PROTECTED_NAMES:
                    rules.setdefault((domain, kind), service["id"])
            skipped.extend({"service": service["id"], "rule": rule} for rule in omitted)
        return {
            "version": commit,
            "services": services,
            "rules": [
                {"domain": domain, "kind": kind, "service_id": sid}
                for (domain, kind), sid in sorted(rules.items())
            ],
            "cidrs": networks,
            "skipped": skipped,
            "at": int(time.time()),
        }

    def apply(self, candidate: dict[str, Any], *, allow_large_change: bool = False) -> int:
        from importlib.resources import files

        system_path = Path(str(files("smartdns").joinpath("data/system-routes.json")))
        if not system_path.is_file():
            system_path = self.manifest.parent / "system-routes.json"
        snapshot = json.loads(system_path.read_text())
        system_rules = snapshot["rules"]
        if not system_rules or not any(r["domain"] == "pornhub.com" for r in system_rules):
            raise ValueError("Invalid protected routing snapshot")
        candidate = dict(candidate)
        candidate["services"] = [s for s in candidate["services"] if s["id"] != SYSTEM_SERVICE] + [
            {
                "id": SYSTEM_SERVICE,
                "name": "System routing",
                "category": "system",
                "capability": "HTTPS",
                "hidden": True,
                "protected": True,
            }
        ]
        system_keys = {(r["domain"], r["kind"]) for r in system_rules}
        rules = [r for r in candidate["rules"] if (r["domain"], r["kind"]) not in system_keys]
        rules += [dict(r, service_id=SYSTEM_SERVICE) for r in system_rules]
        if not 1 <= len(rules) <= 100_000:
            raise ValueError("Invalid catalog size")
        valid_services = {s["id"] for s in candidate["services"]}
        for rule in rules:
            normalize_domain(rule["domain"])
            if rule["kind"] not in ("exact", "suffix") or rule["service_id"] not in valid_services:
                raise ValueError("Invalid catalog rule")
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT COUNT(*) FROM domain_rules").fetchone()[0]
            if current and len(rules) < current * 0.6 and not allow_large_change:
                raise ValueError("Каталог сократился более чем на 40%; требуется ручная проверка")
            for service in candidate["services"]:
                db.execute(
                    "INSERT INTO services(id,name,category,capability,updated,hidden,protected) VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET name=excluded.name,category=excluded.category,capability=excluded.capability,updated=excluded.updated,hidden=excluded.hidden,protected=excluded.protected,enabled=CASE WHEN excluded.protected=1 THEN 1 ELSE services.enabled END",
                    (
                        service["id"],
                        service["name"],
                        service["category"],
                        service["capability"],
                        candidate["at"],
                        int(service.get("hidden", False)),
                        int(service.get("protected", False)),
                    ),
                )
            db.execute("DELETE FROM domain_rules")
            db.executemany(
                "INSERT INTO domain_rules VALUES(?,?,?,?)",
                [
                    (r["domain"], r["kind"], r["service_id"], candidate["version"])
                    for r in rules
                    if r["domain"] not in PROTECTED_NAMES
                ],
            )
            db.execute("DELETE FROM service_cidrs WHERE service_id='telegram'")
            db.executemany(
                "INSERT INTO service_cidrs VALUES('telegram',?,'https://core.telegram.org/resources/cidr.txt')",
                [(n,) for n in candidate["cidrs"]],
            )
            for key, value in {
                "catalog_version": candidate["version"],
                "catalog_updated": candidate["at"],
                "catalog_skipped": candidate["skipped"],
            }.items():
                db.execute(
                    "INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, json.dumps(value)),
                )
            return self.db.bump(db)


class ExitPool:
    """Single configured local egress. Old assignments remain for upgrade compatibility."""

    def __init__(self, db: Database, exit_id: str = "primary"):
        self.db, self.exit_id = db, exit_id

    def choose(
        self, account_id: str, service_id: str, *, excluded: set[str] | None = None
    ) -> dict[str, Any] | None:
        if self.exit_id in (excluded or set()):
            return None
        with self.db.connect(readonly=True) as db:
            row = db.execute(
                "SELECT * FROM exits WHERE id=? AND enabled=1 AND healthy=1", (self.exit_id,)
            ).fetchone()
        return dict(row) if row else None
