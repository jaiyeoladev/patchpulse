"""Small SQLite data layer. One short-lived connection per unit of work (thread-safe)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    mode TEXT NOT NULL,
    trigger TEXT NOT NULL,
    actor TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    stats_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS datasets (
    scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    data_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    entity_name TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    recommendation TEXT NOT NULL DEFAULT '',
    monthly_cost REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open',
    owner TEXT,
    due_date TEXT,
    accepted_until TEXT,
    justification TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    reopen_count INTEGER NOT NULL DEFAULT 0,
    last_scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS ix_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS ix_findings_entity ON findings(entity_type, entity_id);

CREATE TABLE IF NOT EXISTS finding_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_events_finding ON finding_events(finding_id);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
"""


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_dt(value: Any) -> datetime | None:
    """Parse ISO-8601 strings (including Graph's 'Z' and 7-digit fractions)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if text.startswith("0001-01-01"):
        return None
    text = text.replace("Z", "+00:00")
    if "." in text:
        head, _, rest = text.partition(".")
        frac = ""
        tz = ""
        for i, ch in enumerate(rest):
            if not ch.isdigit():
                tz = rest[i:]
                break
            frac += ch
        text = f"{head}.{frac[:6].ljust(6, '0')}{tz}" if frac else f"{head}{tz}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class Database:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def init(self, extra_schema: str = "") -> None:
        with self.conn() as con:
            con.execute("PRAGMA journal_mode = WAL")
            con.executescript(CORE_SCHEMA)
            if extra_schema:
                con.executescript(extra_schema)

    def query(self, sql: str, params: Sequence[Any] | dict = ()) -> list[dict]:
        with self.conn() as con:
            return [dict(r) for r in con.execute(sql, params).fetchall()]

    def one(self, sql: str, params: Sequence[Any] | dict = ()) -> dict | None:
        with self.conn() as con:
            row = con.execute(sql, params).fetchone()
            return dict(row) if row else None

    def scalar(self, sql: str, params: Sequence[Any] | dict = (), default: Any = None) -> Any:
        with self.conn() as con:
            row = con.execute(sql, params).fetchone()
            return default if row is None or row[0] is None else row[0]

    def execute(self, sql: str, params: Sequence[Any] | dict = ()) -> int:
        with self.conn() as con:
            cur = con.execute(sql, params)
            return cur.lastrowid or cur.rowcount

    def audit(self, actor: str, action: str, target: str = "", detail: str = "") -> None:
        self.execute(
            "INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
            (iso(utcnow()), actor, action, target, detail[:2000]),
        )

    # --- datasets -------------------------------------------------------
    def save_dataset(self, scan_id: int, data: dict, keep: int = 5) -> None:
        with self.conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO datasets (scan_id, data_json) VALUES (?, ?)",
                (scan_id, json.dumps(data, default=str)),
            )
            con.execute(
                "DELETE FROM datasets WHERE scan_id NOT IN "
                "(SELECT scan_id FROM datasets ORDER BY scan_id DESC LIMIT ?)",
                (keep,),
            )

    def latest_dataset(self) -> tuple[dict | None, dict]:
        row = self.one(
            "SELECT d.data_json, s.* FROM datasets d JOIN scans s ON s.id = d.scan_id "
            "WHERE s.status = 'success' ORDER BY d.scan_id DESC LIMIT 1"
        )
        if not row:
            return None, {}
        data = json.loads(row.pop("data_json"))
        return row, data
