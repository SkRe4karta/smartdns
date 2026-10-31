from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path("/opt/zelyonka-smartdns-beta/data")
    public_url: str = "https://smartdns.zelyonkin.ru"
    public_ipv4: str = "109.120.185.213"
    agent_socket: Path = Path("/run/zelyonka/agent.sock")
    master_key_file: Path = Path("/opt/zelyonka-smartdns-beta/secrets/master.key")
    telegram_file: Path = Path("/opt/zelyonka-smartdns-beta/secrets/telegram.json")
    agh_url: str = "http://127.0.0.1:3010"
    agh_control_url: str = "http://127.0.0.1:3010"
    api_port: int = 3008
    gateway_port: int = 3007
    dot_port: int = 853
    plain_dns_enabled: bool = False
    plain_dns_port: int = 53
    cert_file: Path = Path("/opt/zelyonka-smartdns-beta/certs/fullchain.pem")
    key_file: Path = Path("/opt/zelyonka-smartdns-beta/certs/privkey.pem")
    frontend_dir: Path = Path("/opt/zelyonka-smartdns-beta/current/frontend/dist")
    legacy_dir: Path = Path("/opt/zelyonka-smartdns-beta/legacy")
    session_days: int = 30
    user_limit: int = 30
    lease_seconds: int = 1800
    test_mode: bool = False

    @property
    def db_path(self) -> Path:
        return self.data_dir / "application.sqlite3"

    @property
    def domain(self) -> str:
        from urllib.parse import urlparse

        return str(urlparse(self.public_url).hostname)

    @property
    def catalog_manifest(self) -> Path:
        from importlib.resources import files

        bundled = Path(str(files("zelyonka").joinpath("data/services.json")))
        return bundled if bundled.is_file() else Path(__file__).resolve().parents[2] / "config/services.json"

    @classmethod
    def load(cls) -> Settings:
        raw: dict[str, Any] = {}
        filename = os.environ.get("ZELYONKA_CONFIG")
        if filename:
            raw = json.loads(Path(filename).read_text())
        fields = cls.__dataclass_fields__
        unknown = set(raw) - set(fields)
        if unknown:
            raise ValueError(f"Unknown configuration fields: {sorted(unknown)}")
        path_fields = {name for name, f in fields.items() if f.type == "Path"}
        for name in path_fields & raw.keys():
            raw[name] = Path(raw[name])
        # Test mode can only be selected programmatically, never by deployed configuration.
        if raw.get("test_mode"):
            raise ValueError("test_mode cannot be enabled in a deployed configuration")
        credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if credential_dir:
            for field, filename in [("master_key_file", "master.key"), ("telegram_file", "telegram.json")]:
                p = Path(credential_dir) / filename
                if p.exists():
                    raw[field] = p
        return cls(**raw)
