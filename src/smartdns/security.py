from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
import threading
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet

PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))
PASSWORD_LOCK = threading.BoundedSemaphore(1)
EXIT_RE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
ACCOUNT_RE = re.compile(r"u[0-9a-f]{12}\Z")
DNS_KEY_RE = re.compile(r"k[a-z2-7]{52}\Z")
LOGIN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{2,39}\Z")
DOMAIN_RE = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_dns_key() -> str:
    return "k" + base64.b32encode(secrets.token_bytes(32)).decode().rstrip("=").lower()


def cipher(path: Path) -> Fernet:
    return Fernet(path.read_bytes().strip())


def validate_password(value: str) -> str:
    if not 12 <= len(value) <= 256:
        raise ValueError("Пароль должен содержать от 12 до 256 символов")
    return value


def password_ok(encoded: str | None, value: str) -> bool:
    try:
        with PASSWORD_LOCK:
            return PASSWORDS.verify(encoded or DUMMY_HASH, value) and encoded is not None
    except VerificationError, InvalidHashError:
        return False


def hash_password(value: str) -> str:
    with PASSWORD_LOCK:
        return PASSWORDS.hash(value)


def public_ipv4(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or not ip.is_global:
        raise ValueError("Требуется публичный IPv4")
    return str(ip)


def public_destination(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError("Некорректный домен") from e
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError("Укажи домен без протокола, порта и пути")
    return value


def equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
