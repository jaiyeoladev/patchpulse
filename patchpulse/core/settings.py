"""Tunable, typed application settings stored in the database."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .db import Database


@dataclass
class SettingDef:
    key: str
    label: str
    type: str  # int | float | bool | text | textarea | json
    default: Any
    help: str = ""
    group: str = "General"
    min: float | None = None
    max: float | None = None
    hidden: bool = False
    choices: list[tuple[str, str]] | None = None


class SettingsError(ValueError):
    pass


class SettingsStore:
    def __init__(self, db: Database, defs: list[SettingDef]):
        self.db = db
        self.defs = {d.key: d for d in defs}

    def _coerce(self, d: SettingDef, raw: Any) -> Any:
        if d.type == "bool":
            if isinstance(raw, bool):
                return raw
            return str(raw).lower() in {"1", "true", "on", "yes"}
        if d.type in ("int", "float"):
            try:
                value: float = float(raw)
            except (TypeError, ValueError) as exc:
                raise SettingsError(f"{d.label}: enter a number.") from exc
            if d.min is not None and value < d.min:
                raise SettingsError(f"{d.label}: must be at least {d.min:g}.")
            if d.max is not None and value > d.max:
                raise SettingsError(f"{d.label}: must be at most {d.max:g}.")
            return int(value) if d.type == "int" else value
        if d.type == "json":
            if isinstance(raw, (dict, list)):
                return raw
            try:
                return json.loads(raw or "null")
            except json.JSONDecodeError as exc:
                raise SettingsError(f"{d.label}: invalid JSON ({exc.msg}).") from exc
        value = "" if raw is None else str(raw)
        if d.choices and value not in {c[0] for c in d.choices}:
            raise SettingsError(f"{d.label}: choose one of the listed options.")
        return value

    def all(self) -> dict[str, Any]:
        stored = {r["key"]: r["value"] for r in self.db.query("SELECT key, value FROM settings")}
        out: dict[str, Any] = {}
        for key, d in self.defs.items():
            if key in stored:
                try:
                    out[key] = self._coerce(d, json.loads(stored[key]))
                    continue
                except (SettingsError, json.JSONDecodeError):
                    pass
            out[key] = d.default
        return out

    def get(self, key: str) -> Any:
        return self.all()[key]

    def set_many(self, values: dict[str, Any], actor: str) -> list[str]:
        changed: list[str] = []
        current = self.all()
        coerced = {}
        for key, raw in values.items():
            d = self.defs.get(key)
            if d is None:
                continue
            coerced[key] = self._coerce(d, raw)
        with self.db.conn() as con:
            for key, value in coerced.items():
                if current.get(key) != value:
                    changed.append(key)
                con.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, json.dumps(value)),
                )
        if changed:
            self.db.audit(actor, "settings.update", "settings", ", ".join(changed))
        return changed

    def grouped(self) -> list[tuple[str, list[SettingDef]]]:
        groups: dict[str, list[SettingDef]] = {}
        for d in self.defs.values():
            if d.hidden:
                continue
            groups.setdefault(d.group, []).append(d)
        return list(groups.items())
