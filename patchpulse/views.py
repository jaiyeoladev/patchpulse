"""PatchPulse pages: dashboard, devices, vulnerabilities, owner chase list and CSV import."""

from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import Depends, FastAPI, Request, UploadFile
from fastapi.responses import HTMLResponse

from .catalog import normalise_severity, severity_from_cvss
from .core.auth import current_user, require_admin_form, require_user
from .core.context import Context
from .core.db import iso, parse_dt, utcnow
from .core.findings import SEVERITY_RANK, SEVERITY_WEIGHT
from .core.web import page_render, redirect

DEVICE_RULES = ("EPC-001", "EPC-002", "EPC-003", "EPC-004", "EPC-005", "EPC-006", "EPC-007", "EPC-008", "EPC-009")
CSV_ALIASES = {
    "hostname": ["hostname", "host", "host_name", "asset", "asset_name", "device", "device_name", "computer",
                 "computer_name", "dns_name", "netbios_name", "name"],
    "cve": ["cve", "cve_id", "cves", "cve_ids", "vulnerability_id"],
    "cvss": ["cvss", "cvss_score", "cvss3", "cvss_v3", "cvss3_base_score", "cvss_v3_base_score", "base_score", "score"],
    "severity": ["severity", "risk", "risk_rating", "criticality"],
    "title": ["title", "name", "vulnerability", "vulnerability_name", "plugin_name", "synopsis", "description"],
    "first_seen": ["first_seen", "first_found", "first_detected", "first_discovered", "created", "discovered", "detected"],
    "product": ["product", "software", "application", "affected_product"],
    "remediation": ["remediation", "solution", "fix", "recommendation"],
}


def _devices(ctx: Context) -> tuple[list[dict], dict]:
    _, data = ctx.latest()
    return data.get("devices", []), data


def _active_vulns(ctx: Context) -> list[dict]:
    rows, _ = ctx.findings.search(status="active", rule_id="VUL-001", limit=200000)
    return rows


def dashboard(ctx: Context) -> dict:
    devices, data = _devices(ctx)
    sources = data.get("sources", {})
    settings = ctx.settings.all()
    edr_platforms = {p.strip().lower() for p in (settings["edr_platforms"] or "").splitlines() if p.strip()}
    eligible = [d for d in devices if d.get("platform", "").lower() in edr_platforms and not d.get("scanner_only")]
    with_edr = [d for d in eligible if d.get("falcon")]
    intune = [d for d in devices if d.get("intune")]
    compliant = [d for d in intune if (d["intune"].get("complianceState") or "").lower() == "compliant"]
    enc_scope = [d for d in intune if d.get("platform") in ("Windows", "macOS")]
    encrypted = [d for d in enc_scope if d["intune"].get("encrypted")]

    vulns = _active_vulns(ctx)
    overdue = [v for v in vulns if v["overdue"]]
    kev = [v for v in vulns if v["details"].get("kev")]
    sev_counts = Counter(v["severity"] for v in vulns)
    ce_breaches = [v for v in vulns if (v["details"].get("cvss") or 0) >= 7 and v["overdue"]]
    ce_hosts = len({v["entity_id"] for v in ce_breaches})

    # MTTR for vulnerabilities fixed in the last 90 days
    since = iso(utcnow() - timedelta(days=90))
    fixed = ctx.db.query(
        "SELECT first_seen, resolved_at, severity FROM findings WHERE rule_id='VUL-001' AND status='resolved' "
        "AND resolved_at >= ?", (since,))
    durations = [(parse_dt(r["resolved_at"]) - parse_dt(r["first_seen"])).days for r in fixed
                 if parse_dt(r["resolved_at"]) and parse_dt(r["first_seen"])]
    mttr = sum(durations) / len(durations) if durations else None

    # weekly open-vulnerability trend (last 8 weeks)
    all_v = ctx.db.query("SELECT first_seen, resolved_at FROM findings WHERE rule_id='VUL-001'")
    trend = []
    now = utcnow()
    for w in range(7, -1, -1):
        t = now - timedelta(weeks=w)
        n = 0
        for r in all_v:
            fs, ra = parse_dt(r["first_seen"]), parse_dt(r["resolved_at"])
            if fs and fs <= t and (ra is None or ra > t):
                n += 1
        trend.append((t.strftime("%d %b"), n))

    owners: dict[str, int] = defaultdict(int)
    for v in overdue:
        owners[v["owner"] or "Unassigned"] += 1
    by_owner = sorted(owners.items(), key=lambda x: -x[1])[:8]

    cves: dict[str, dict] = {}
    for v in vulns:
        c = cves.setdefault(v["details"]["cve"], {"cve": v["details"]["cve"], "hosts": 0, "overdue": 0,
                                                  "severity": v["severity"], "kev": v["details"].get("kev"),
                                                  "cvss": v["details"].get("cvss")})
        c["hosts"] += 1
        c["overdue"] += 1 if v["overdue"] else 0
    top_cves = sorted(cves.values(), key=lambda c: (SEVERITY_RANK[c["severity"]], -c["hosts"]))[:8]

    risk: dict[str, float] = defaultdict(float)
    names: dict[str, str] = {}
    for f in ctx.db.query(
        "SELECT entity_id, entity_name, severity, details_json FROM findings "
        "WHERE status IN ('open','acknowledged') AND entity_type='device'"
    ):
        w = SEVERITY_WEIGHT[f["severity"]] * (2 if '"kev": true' in f["details_json"] else 1)
        risk[f["entity_id"]] += w
        names[f["entity_id"]] = f["entity_name"]
    top_devices = [(names[k], v, "bar-high") for k, v in sorted(risk.items(), key=lambda x: -x[1])[:8]]
    device_issues = ctx.db.query(
        "SELECT rule_id, COUNT(*) n FROM findings WHERE status IN ('open','acknowledged') AND rule_id LIKE 'EPC-%' "
        "GROUP BY rule_id ORDER BY n DESC")
    return {
        "devices_total": len(devices),
        "edr_coverage": len(with_edr) / len(eligible) if eligible and sources.get("falcon") else None,
        "edr_missing": len(eligible) - len(with_edr),
        "compliance": len(compliant) / len(intune) if intune else None,
        "noncompliant": len(intune) - len(compliant),
        "encryption": len(encrypted) / len(enc_scope) if enc_scope else None,
        "vuln_open": len(vulns),
        "vuln_overdue": len(overdue),
        "sla_compliance": 1 - len(overdue) / len(vulns) if vulns else 1.0,
        "kev_open": len(kev),
        "ce_breaches": len(ce_breaches),
        "ce_hosts": ce_hosts,
        "mttr": mttr,
        "trend": trend,
        "by_owner": by_owner,
        "top_cves": top_cves,
        "top_devices": top_devices,
        "sev_segments": [(s.capitalize(), sev_counts.get(s, 0), f"bar-{s}") for s in ("critical", "high", "medium", "low")],
        "sev_counts": sev_counts,
        "device_issues": [(f"{r['rule_id']} · {ctx.spec.rules[r['rule_id']].title}", r["n"]) for r in device_issues
                          if r["rule_id"] in ctx.spec.rules],
        "sources": sources,
    }


def entity_link(f: dict) -> str | None:
    return f"/devices/{f['entity_id']}" if f["entity_type"] == "device" else None


def report_context(ctx: Context) -> dict:
    return {"pp": dashboard(ctx)}


def _map_columns(header: list[str]) -> dict[str, str]:
    norm = {h: h.strip().lower().replace(" ", "_").replace("-", "_") for h in header}
    mapping: dict[str, str] = {}
    for field, aliases in CSV_ALIASES.items():
        for alias in aliases:
            match = next((h for h, n in norm.items() if n == alias and h not in mapping.values()), None)
            if match:
                mapping[field] = match
                break
    return mapping


def parse_scanner_csv(text: str, max_rows: int = 50000) -> tuple[list[dict], list[str]]:
    reader = csv.DictReader(io.StringIO(text))
    mapping = _map_columns(reader.fieldnames or [])
    problems = []
    if "hostname" not in mapping or "cve" not in mapping:
        return [], ["The CSV needs a host column (hostname/host/asset) and a CVE column (cve/cve_id)."]
    rows = []
    for row in reader:
        if len(rows) >= max_rows:
            problems.append(f"Stopped after {max_rows} rows.")
            break
        host = (row.get(mapping["hostname"]) or "").strip()
        cves = [c.strip().upper() for c in (row.get(mapping["cve"]) or "").replace(";", ",").split(",") if c.strip()]
        if not host or not cves:
            continue
        cvss = None
        if "cvss" in mapping:
            try:
                cvss = float((row.get(mapping["cvss"]) or "").strip() or "nan")
                cvss = None if cvss != cvss else max(0.0, min(10.0, cvss))
            except ValueError:
                cvss = None
        sev = normalise_severity(row.get(mapping["severity"])) if "severity" in mapping else None
        sev = sev or severity_from_cvss(cvss)
        first = parse_dt(row.get(mapping["first_seen"])) if "first_seen" in mapping else None
        for cve in cves:
            if not cve.startswith("CVE-"):
                continue
            rows.append({
                "hostname": host[:200], "cve": cve[:40], "cvss": cvss, "severity": sev,
                "title": (row.get(mapping.get("title", ""), "") or "")[:240],
                "first_seen": iso(first) if first else None,
                "product": (row.get(mapping.get("product", ""), "") or "")[:200],
                "remediation": (row.get(mapping.get("remediation", ""), "") or "")[:500],
            })
    return rows, problems


def register_routes(app: FastAPI, ctx: Context) -> None:
    render = page_render(ctx)
    db = ctx.db

    def _flagged() -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = defaultdict(list)
        for r in db.query(
            "SELECT entity_id, rule_id, severity, due_date FROM findings WHERE status IN ('open','acknowledged') "
            "AND entity_type='device'"
        ):
            out[r["entity_id"]].append(r)
        return out

    @app.get("/devices", response_class=HTMLResponse)
    async def devices(request: Request, view: str = "all", platform: str = "", q: str = "", user=Depends(require_user)):
        devs, data = _devices(ctx)
        flagged = _flagged()
        today = utcnow().date().isoformat()
        rows = []
        q_l = q.strip().lower()
        for d in devs:
            fs = flagged.get(d["key"], [])
            rules = {f["rule_id"] for f in fs}
            vulns = [f for f in fs if f["rule_id"] == "VUL-001"]
            if view == "issues" and not (rules - {"VUL-001"}):
                continue
            if view == "no_edr" and "EPC-006" not in rules:
                continue
            if view == "unmanaged" and "EPC-007" not in rules:
                continue
            if view == "unsupported" and not rules & {"EPC-004", "EPC-005"}:
                continue
            if view == "overdue" and not any(v["due_date"] and v["due_date"] < today for v in vulns):
                continue
            if platform and d.get("platform") != platform:
                continue
            if q_l and q_l not in d["name"].lower() and q_l not in (d.get("user") or "").lower():
                continue
            rows.append({**d, "rules": sorted(rules - {"VUL-001"}), "vulns": len(vulns),
                         "crit": sum(1 for v in vulns if v["severity"] in ("critical", "high")),
                         "overdue": sum(1 for v in vulns if v["due_date"] and v["due_date"] < today)})
        rows.sort(key=lambda r: (-(r["overdue"] * 10 + r["crit"] * 3 + len(r["rules"])), r["name"].lower()))
        platforms = sorted({d.get("platform", "") for d in devs if d.get("platform")})
        return render(request, "devices.html", rows=rows[:1000], total=len(rows), view=view, platform=platform,
                      platforms=platforms, q=q, sources=data.get("sources", {}), title="Devices")

    @app.get("/devices/{key}", response_class=HTMLResponse)
    async def device_detail(request: Request, key: str, user=Depends(require_user)):
        devs, _ = _devices(ctx)
        d = next((x for x in devs if x["key"] == key), None)
        if not d:
            return render(request, "error.html", status_code=404, title="Not found",
                          message="That device was not in the latest scan.")
        findings, _ = ctx.findings.search(status="active", entity_type="device", entity_id=key, limit=1000)
        issues = [f for f in findings if f["rule_id"] != "VUL-001"]
        vulns = [f for f in findings if f["rule_id"] == "VUL-001"]
        return render(request, "device.html", d=d, issues=issues, vulns=vulns, title=d["name"])

    @app.get("/vulnerabilities", response_class=HTMLResponse)
    async def vulnerabilities(request: Request, severity: str = "", kev: str = "", q: str = "", user=Depends(require_user)):
        vulns = _active_vulns(ctx)
        groups: dict[str, dict] = {}
        for v in vulns:
            det = v["details"]
            g = groups.setdefault(det["cve"], {"cve": det["cve"], "title": v["title"].split(": ", 1)[-1],
                                               "severity": v["severity"], "cvss": det.get("cvss"), "kev": det.get("kev"),
                                               "product": det.get("product"), "hosts": [], "overdue": 0,
                                               "oldest": v["first_seen"], "next_due": v["due_date"]})
            g["hosts"].append(v["entity_name"])
            g["overdue"] += 1 if v["overdue"] else 0
            g["oldest"] = min(g["oldest"], v["first_seen"])
            if v["due_date"] and (not g["next_due"] or v["due_date"] < g["next_due"]):
                g["next_due"] = v["due_date"]
            if SEVERITY_RANK[v["severity"]] < SEVERITY_RANK[g["severity"]]:
                g["severity"] = v["severity"]
        rows = list(groups.values())
        if severity:
            rows = [r for r in rows if r["severity"] == severity]
        if kev == "1":
            rows = [r for r in rows if r["kev"]]
        if q.strip():
            ql = q.strip().lower()
            rows = [r for r in rows if ql in r["cve"].lower() or ql in (r["title"] or "").lower()
                    or ql in (r["product"] or "").lower()]
        rows.sort(key=lambda r: (not r["kev"], SEVERITY_RANK[r["severity"]], -len(r["hosts"])))
        return render(request, "vulnerabilities.html", rows=rows, severity=severity, kev=kev, q=q,
                      instances=len(vulns), title="Vulnerabilities")

    @app.get("/owners", response_class=HTMLResponse)
    async def owners(request: Request, user=Depends(require_user)):
        rows, _ = ctx.findings.search(status="active", limit=200000)
        table: dict[str, dict] = {}
        for f in rows:
            o = f["owner"] or "Unassigned"
            t = table.setdefault(o, {"owner": o, "open": 0, "overdue": 0, "critical": 0, "high": 0, "kev": 0,
                                     "oldest_overdue": 0, "devices": set()})
            t["open"] += 1
            t["devices"].add(f["entity_id"])
            if f["overdue"]:
                t["overdue"] += 1
                t["oldest_overdue"] = max(t["oldest_overdue"], f["days_overdue"])
            if f["severity"] in ("critical", "high"):
                t[f["severity"]] += 1
            if f["details"].get("kev"):
                t["kev"] += 1
        out = sorted(table.values(), key=lambda t: (-t["overdue"], -t["critical"], -t["open"]))
        for t in out:
            t["devices"] = len(t["devices"])
        return render(request, "owners.html", rows=out, owner_rules=ctx.settings.get("owner_rules"), title="Owners")

    @app.get("/import", response_class=HTMLResponse)
    async def import_page(request: Request, user=Depends(require_user)):
        sources = db.query(
            "SELECT source, COUNT(*) n, COUNT(DISTINCT hostname) hosts, MAX(imported_at) imported_at "
            "FROM imported_vulns GROUP BY source ORDER BY imported_at DESC")
        return render(request, "import.html", sources=sources, aliases=CSV_ALIASES, title="Import")

    @app.post("/import")
    async def import_upload(request: Request, file: UploadFile, form=Depends(require_admin_form)):
        actor = current_user(request)["name"]
        flash = request.session.setdefault("flash", [])
        source = str(form.get("source", "")).strip()[:80] or "CSV import"
        raw = await file.read(20_000_001)
        if len(raw) > 20_000_000:
            flash.append(["error", "File too large (20 MB max)."])
            return redirect("/import")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
        rows, problems = parse_scanner_csv(text)
        if not rows:
            flash.append(["error", "No vulnerability rows found. " + " ".join(problems)])
            return redirect("/import")
        now = iso(utcnow())
        with db.conn() as con:
            con.execute("DELETE FROM imported_vulns WHERE source = ?", (source,))
            con.executemany(
                """INSERT INTO imported_vulns (source, hostname, cve, title, cvss, severity, first_seen, product,
                remediation, imported_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                [(source, r["hostname"], r["cve"], r["title"], r["cvss"], r["severity"], r["first_seen"], r["product"],
                  r["remediation"], now) for r in rows],
            )
        db.audit(actor, "import.csv", f"source:{source}", f"{len(rows)} rows from {file.filename}")
        flash.append(["success", f"Imported {len(rows)} vulnerability rows into “{source}”. Run a scan to apply them."])
        for p in problems:
            flash.append(["info", p])
        return redirect("/import")

    @app.post("/import/delete")
    async def import_delete(request: Request, form=Depends(require_admin_form)):
        actor = current_user(request)["name"]
        source = str(form.get("source", ""))
        n = db.execute("DELETE FROM imported_vulns WHERE source = ?", (source,))
        db.audit(actor, "import.delete", f"source:{source}", f"{n} rows")
        request.session.setdefault("flash", []).append(["success", f"Removed “{source}”. Its findings resolve on the next scan."])
        return redirect("/import")
