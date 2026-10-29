"""Shared application context handed to every product module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi.templating import Jinja2Templates

from .config import Config
from .db import Database
from .findings import FindingStore
from .settings import SettingsStore
from .spec import AppSpec


@dataclass
class Context:
    spec: AppSpec
    config: Config
    db: Database
    settings: SettingsStore
    findings: FindingStore
    templates: Jinja2Templates | None = None
    scanner: Any = None
    state: dict[str, Any] = field(default_factory=dict)

    def latest(self) -> tuple[dict | None, dict]:
        """(scan row, dataset) for the most recent successful scan."""
        return self.db.latest_dataset()

    @property
    def mode(self) -> str:
        return "demo" if self.config.demo_mode else "live"
