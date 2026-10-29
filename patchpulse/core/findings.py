"""Findings model, lifecycle and persistence.

A finding is identified by a stable fingerprint (rule + entity + optional key), so the same
problem found on every scan updates one record instead of creating duplicates. Findings that
disappear from a scan are auto-resolved; resolved findings that reappear are reopened.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from .db import Database, iso, parse_dt, utcnow

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

STATUSES = ["open", "acknowledged", "accepted", "resolved"]
ACTIVE_STATUSES = ("open", "acknowledged")
STATUS_LABELS = {
    "open": "Open",
    "acknowledged": "In progress",
    "accepted": "Risk accepted",
    "resolved": "Resolved",
}
MAX_ACCEPT_DAYS = 365


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    entity_type: str
    entity_id: str
    entity_name: str
    details: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    monthly_cost: float = 0.0
    due_date: str | None = None
    owner_hint: str | None = None
    first_seen: str | None = None
    key: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"Unknown severity {self.severity!r}")

    @property
    def fingerprint(self) -> str:
        raw = "|".join([self.rule_id, self.entity_type, str(self.entity_id).lower(), self.key])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass
class RuleInfo:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    reference: str = ""


class FindingError(ValueError):
    pass


def _row(row: dict) -> dict:
    row["details"] = json.loads(row.pop("details_json") or "{}")
    due = parse_dt(row.get("due_date"))
    row["overdue"] = bool(
        due and row["status"] in ACTIVE_STATUSES and due.date() < utcnow().date()
    )
    row["days_overdue"] = (utcnow().date() - due.date()).days if row["overdue"] and due else 0
    return row


class FindingStore:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ sync
    def sync(self, scan_id: int, findings: list[Finding], now: datetime | None = None) -> dict:
        now = now or utcnow()
        now_s = iso(now)
        today = now.date().isoformat()
        unique: dict[str, Finding] = {}
        for f in findings:
            fp = f.fingerprint
            prev = unique.get(fp)
            if prev is None or SEVERITY_RANK[f.severity] < SEVERITY_RANK[prev.severity]:
                unique[fp] = f

        stats = {"new": 0, "reopened": 0, "updated": 0, "resolved": 0, "exceptions_expired": 0}
        with self.db.conn() as con:
            existing = {
                r["fingerprint"]: dict(r)
                for r in con.execute(
                    "SELECT id, fingerprint, status, owner, accepted_until, first_seen FROM findings"
                ).fetchall()
            }
            events: list[tuple[int, str, str, str, str]] = []
            for fp, f in unique.items():
                details = json.dumps(f.details, default=str)
                ex = existing.get(fp)
                if ex is None:
                    cur = con.execute(
                        """INSERT INTO findings (fingerprint, rule_id, severity, title, entity_type,
                        entity_id, entity_name, details_json, recommendation, monthly_cost, status,
                        owner, due_date, first_seen, last_seen, last_scan_id)
                        VALUES (?,?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?)""",
                        (
                            fp, f.rule_id, f.severity, f.title, f.entity_type, str(f.entity_id),
                            f.entity_name, details, f.recommendation, round(f.monthly_cost, 2),
                            f.owner_hint, f.due_date, f.first_seen or now_s, now_s, scan_id,
                        ),
                    )
                    stats["new"] += 1
                    events.append((cur.lastrowid, now_s, "system", "created", f"Detected by {f.rule_id}"))
                    continue

                status = ex["status"]
                event = None
                if status == "resolved":
                    status = "open"
                    stats["reopened"] += 1
                    event = ("reopened", "Issue detected again by a scan")
                elif status == "accepted" and (ex["accepted_until"] or "") < today:
                    status = "open"
                    stats["exceptions_expired"] += 1
                    event = ("exception_expired", f"Risk acceptance expired on {ex['accepted_until']}")
                else:
                    stats["updated"] += 1
                con.execute(
                    """UPDATE findings SET severity=?, title=?, entity_name=?, details_json=?,
                    recommendation=?, monthly_cost=?, due_date=COALESCE(?, due_date), status=?,
                    owner=COALESCE(owner, ?), last_seen=?, last_scan_id=?,
                    resolved_at=CASE WHEN ?='open' AND status='resolved' THEN NULL ELSE resolved_at END,
                    reopen_count=reopen_count + CASE WHEN status='resolved' THEN 1 ELSE 0 END,
                    accepted_until=CASE WHEN ?='open' AND status='accepted' THEN NULL ELSE accepted_until END
                    WHERE id=?""",
                    (
                        f.severity, f.title, f.entity_name, details, f.recommendation,
                        round(f.monthly_cost, 2), f.due_date, status, f.owner_hint, now_s, scan_id,
                        status, status, ex["id"],
                    ),
                )
                if event:
                    events.append((ex["id"], now_s, "system", event[0], event[1]))

            gone = [
                ex for fp, ex in existing.items() if fp not in unique and ex["status"] != "resolved"
            ]
            for ex in gone:
                con.execute(
                    "UPDATE findings SET status='resolved', resolved_at=? WHERE id=?",
                    (now_s, ex["id"]),
                )
                events.append((ex["id"], now_s, "system", "auto_resolved", "No longer detected by the latest scan"))
            stats["resolved"] = len(gone)
            con.executemany(
                "INSERT INTO finding_events (finding_id, ts, actor, event, detail) VALUES (?,?,?,?,?)",
                events,
            )
        return stats

    # ----------------------------------------------------------------- reads
    def get(self, finding_id: int) -> dict | None:
        row = self.db.one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if not row:
            return None
        row = _row(row)
        row["events"] = self.db.query(
            "SELECT * FROM finding_events WHERE finding_id = ? ORDER BY id DESC", (finding_id,)
        )
        return row

    def search(
        self,
        status: str = "active",
        severity: str = "",
        rule_id: str = "",
        rule_prefix: str = "",
        entity_type: str = "",
        entity_id: str = "",
        owner: str = "",
        q: str = "",
        overdue: bool = False,
        sort: str = "severity",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        where, params = ["1=1"], []
        if status == "active":
            where.append("status IN ('open','acknowledged')")
        elif status in STATUSES:
            where.append("status = ?")
            params.append(status)
        if severity in SEVERITY_RANK:
            where.append("severity = ?")
            params.append(severity)
        if rule_id:
            where.append("rule_id = ?")
            params.append(rule_id)
        if rule_prefix:
            where.append("rule_id LIKE ?")
            params.append(rule_prefix + "%")
        if entity_type:
            where.append("entity_type = ?")
            params.append(entity_type)
        if entity_id:
            where.append("lower(entity_id) = lower(?)")
            params.append(entity_id)
        if owner == "__none__":
            where.append("(owner IS NULL OR owner = '')")
        elif owner:
            where.append("owner = ?")
            params.append(owner)
        if q:
            where.append("(title LIKE ? OR entity_name LIKE ? OR details_json LIKE ?)")
            like = f"%{q}%"
            params += [like, like, like]
        if overdue:
            where.append("status IN ('open','acknowledged') AND due_date IS NOT NULL AND substr(due_date,1,10) < ?")
            params.append(utcnow().date().isoformat())
        sev_order = "CASE severity " + " ".join(
            f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)
        ) + " END"
        order = {
            "severity": f"{sev_order}, monthly_cost DESC, id",
            "cost": "monthly_cost DESC, id",
            "newest": "first_seen DESC, id DESC",
            "due": "CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, due_date, id",
            "entity": "entity_name COLLATE NOCASE, id",
        }.get(sort, f"{sev_order}, id")
        clause = " AND ".join(where)
        total = self.db.scalar(f"SELECT COUNT(*) FROM findings WHERE {clause}", params, 0)
        rows = self.db.query(
            f"SELECT * FROM findings WHERE {clause} ORDER BY {order} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        return [_row(r) for r in rows], total

    def summary(self, rule_prefix: str = "") -> dict:
        extra = " AND rule_id LIKE ?" if rule_prefix else ""
        params = [rule_prefix + "%"] if rule_prefix else []
        by_sev = {s: 0 for s in SEVERITIES}
        for r in self.db.query(
            f"SELECT severity, COUNT(*) n FROM findings WHERE status IN ('open','acknowledged'){extra} GROUP BY severity",
            params,
        ):
            by_sev[r["severity"]] = r["n"]
        by_status = {s: 0 for s in STATUSES}
        for r in self.db.query(
            f"SELECT status, COUNT(*) n FROM findings WHERE 1=1{extra} GROUP BY status", params
        ):
            by_status[r["status"]] = r["n"]
        by_rule = self.db.query(
            f"""SELECT rule_id, COUNT(*) n, SUM(monthly_cost) cost FROM findings
            WHERE status IN ('open','acknowledged'){extra} GROUP BY rule_id ORDER BY n DESC""",
            params,
        )
        cost = self.db.scalar(
            f"SELECT SUM(monthly_cost) FROM findings WHERE status IN ('open','acknowledged'){extra}",
            params,
            0.0,
        )
        return {
            "by_severity": by_sev,
            "by_status": by_status,
            "by_rule": by_rule,
            "active": sum(by_sev.values()),
            "monthly_cost": float(cost or 0.0),
        }

    def owners(self) -> list[str]:
        return [
            r["owner"]
            for r in self.db.query(
                "SELECT DISTINCT owner FROM findings WHERE owner IS NOT NULL AND owner != '' ORDER BY owner"
            )
        ]

    # ------------------------------------------------------------- actions
    def apply(
        self,
        finding_id: int,
        action: str,
        actor: str,
        owner: str = "",
        justification: str = "",
        accepted_until: str = "",
        comment: str = "",
    ) -> dict:
        row = self.db.one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if not row:
            raise FindingError("Finding not found.")
        now_s = iso(utcnow())
        updates: dict[str, Any] = {}
        detail = ""
        if action == "acknowledge":
            if row["status"] not in ("open",):
                raise FindingError("Only open findings can be marked in progress.")
            updates["status"] = "acknowledged"
            detail = "Marked in progress"
        elif action == "reopen":
            if row["status"] == "open":
                raise FindingError("Finding is already open.")
            updates.update(status="open", resolved_at=None, accepted_until=None)
            detail = "Reopened manually"
        elif action == "resolve":
            if row["status"] == "resolved":
                raise FindingError("Finding is already resolved.")
            updates.update(status="resolved", resolved_at=now_s)
            detail = "Marked resolved (it will reopen if the next scan still detects it)"
        elif action == "accept":
            justification = justification.strip()
            if len(justification) < 10:
                raise FindingError("A justification of at least 10 characters is required.")
            try:
                until = date.fromisoformat(accepted_until)
            except ValueError as exc:
                raise FindingError("A valid expiry date is required for a risk acceptance.") from exc
            today = utcnow().date()
            if until <= today:
                raise FindingError("The expiry date must be in the future.")
            if until > today + timedelta(days=MAX_ACCEPT_DAYS):
                raise FindingError(f"Risk acceptances can last at most {MAX_ACCEPT_DAYS} days.")
            updates.update(status="accepted", accepted_until=until.isoformat(), justification=justification)
            detail = f"Risk accepted until {until.isoformat()}: {justification}"
        elif action == "assign":
            owner = owner.strip()[:120]
            updates["owner"] = owner or None
            detail = f"Owner set to {owner}" if owner else "Owner cleared"
        elif action == "comment":
            comment = comment.strip()
            if not comment:
                raise FindingError("Comment cannot be empty.")
            detail = comment[:2000]
        else:
            raise FindingError(f"Unknown action {action!r}.")

        with self.db.conn() as con:
            if updates:
                cols = ", ".join(f"{k} = ?" for k in updates)
                con.execute(f"UPDATE findings SET {cols} WHERE id = ?", [*updates.values(), finding_id])
            con.execute(
                "INSERT INTO finding_events (finding_id, ts, actor, event, detail) VALUES (?,?,?,?,?)",
                (finding_id, now_s, actor, action, detail),
            )
        self.db.audit(actor, f"finding.{action}", f"finding:{finding_id}", detail)
        return self.get(finding_id) or {}


def due_from(start: datetime | str | None, days: int | float | None) -> str | None:
    if days is None or days <= 0:
        return None
    start_dt = parse_dt(start) if not isinstance(start, datetime) else start
    if start_dt is None:
        start_dt = utcnow()
    return (start_dt + timedelta(days=int(days))).date().isoformat()
