"""The contract each product implements to plug into the shared web shell."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .findings import Finding, RuleInfo
from .settings import SettingDef

if TYPE_CHECKING:
    from fastapi import FastAPI

    from .context import Context


@dataclass
class NavItem:
    label: str
    href: str


@dataclass
class AppSpec:
    slug: str
    name: str
    tagline: str
    description: str
    package_dir: Path
    nav: list[NavItem]
    rules: dict[str, RuleInfo]
    setting_defs: list[SettingDef]
    collect_demo: Callable[[Context], dict]
    collect_live: Callable[[Context], dict]
    analyse: Callable[[dict, dict[str, Any], Context], list[Finding]]
    dashboard: Callable[[Context], dict]
    register_routes: Callable[[FastAPI, Context], None]
    live_requirements: Callable[[Context], list[str]]
    schema_sql: str = ""
    entity_link: Callable[[dict], str | None] = lambda finding: None
    report_context: Callable[[Context], dict] = lambda ctx: {}
    on_startup: Callable[[Context], None] | None = None
    graph_permissions: list[str] = field(default_factory=list)

    @property
    def templates_dir(self) -> Path:
        return self.package_dir / "templates"
