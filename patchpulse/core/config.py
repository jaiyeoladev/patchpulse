"""Runtime configuration loaded from environment variables (and an optional .env file)."""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

TRUE_VALUES = {"1", "true", "yes", "on"}


def load_dotenv(path: str | os.PathLike = ".env") -> None:
    """Minimal .env loader. Existing environment variables always win."""
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in TRUE_VALUES


def env_str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return default if value is None else value.strip()


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


DEMO_PASSWORD = "changeme-demo"


@dataclass
class Config:
    slug: str
    demo_mode: bool = True
    database_path: str = "data/app.db"
    secret_key: str = ""
    admin_username: str = "admin"
    admin_password: str = ""
    viewer_username: str = "auditor"
    viewer_password: str = ""
    api_token: str = ""
    session_cookie_secure: bool = False
    scan_interval_hours: float = 0.0
    currency_symbol: str = "£"
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    graph_base: str = "https://graph.microsoft.com/v1.0"
    graph_beta_base: str = "https://graph.microsoft.com/beta"
    authority: str = "https://login.microsoftonline.com"
    warnings: list[str] = field(default_factory=list)
    ephemeral_secret: bool = False

    @classmethod
    def from_env(cls, slug: str, dotenv: bool = True) -> Config:
        if dotenv:
            load_dotenv()
        demo = env_bool("DEMO_MODE", True)
        cfg = cls(
            slug=slug,
            demo_mode=demo,
            database_path=env_str("DATABASE_PATH", f"data/{slug}.db"),
            secret_key=env_str("SECRET_KEY"),
            admin_username=env_str("ADMIN_USERNAME", "admin") or "admin",
            admin_password=env_str("ADMIN_PASSWORD"),
            viewer_username=env_str("VIEWER_USERNAME", "auditor") or "auditor",
            viewer_password=env_str("VIEWER_PASSWORD"),
            api_token=env_str("API_TOKEN"),
            session_cookie_secure=env_bool("SESSION_COOKIE_SECURE", False),
            scan_interval_hours=env_float("SCAN_INTERVAL_HOURS", 0.0),
            currency_symbol=env_str("CURRENCY_SYMBOL", "£") or "£",
            tenant_id=env_str("AZURE_TENANT_ID"),
            client_id=env_str("AZURE_CLIENT_ID"),
            client_secret=env_str("AZURE_CLIENT_SECRET"),
            graph_base=env_str("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0").rstrip("/"),
            graph_beta_base=env_str("GRAPH_BETA_BASE_URL", "https://graph.microsoft.com/beta").rstrip("/"),
            authority=env_str("AZURE_AUTHORITY", "https://login.microsoftonline.com").rstrip("/"),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not self.secret_key:
            self.secret_key = secrets.token_urlsafe(48)
            self.ephemeral_secret = True
            self.warnings.append(
                "SECRET_KEY is not set: a random key was generated, so sessions end on restart."
            )
        if not self.admin_password:
            if self.demo_mode:
                self.admin_password = DEMO_PASSWORD
                self.warnings.append(
                    f"ADMIN_PASSWORD is not set: demo login is {self.admin_username} / {DEMO_PASSWORD}."
                )
            else:
                raise RuntimeError("ADMIN_PASSWORD must be set when DEMO_MODE=false.")
        if not self.demo_mode and len(self.admin_password) < 12:
            raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters when DEMO_MODE=false.")
        for w in self.warnings:
            log.warning(w)

    @property
    def graph_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    def env(self, name: str, default: str = "") -> str:
        """Read an app-specific environment variable."""
        return env_str(name, default)

    def env_bool(self, name: str, default: bool = False) -> bool:
        return env_bool(name, default)
