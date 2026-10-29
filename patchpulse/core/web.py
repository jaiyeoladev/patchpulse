"""Builds the FastAPI application: middleware, shared pages, JSON API and the product's routes."""

from __future__ import annotations

import csv
import io
import json
import logging
import math
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import ChoiceLoader, Environment, FileSystemLoader, select_autoescape
from starlette.middleware.sessions import SessionMiddleware

from . import charts
from .auth import (
    ROLE_ADMIN,
    ApiUnauthorized,
    Forbidden,
    LoginRequired,
    LoginThrottle,
    check_credentials,
    client_key,
    csrf_token,
    current_user,
    login,
    require_admin_form,
    require_api,
    require_user,
    safe_next,
)
from .config import Config
from .context import Context
from .db import Database, parse_dt, utcnow
from .findings import (
    MAX_ACCEPT_DAYS,
    SEVERITIES,
    STATUS_LABELS,
    STATUSES,
    FindingError,
    FindingStore,
)
from .scanner import ScanInProgress, Scanner
from .settings import SettingsError, SettingsStore
from .spec import AppSpec

log = logging.getLogger(__name__)
CORE_DIR = Path(__file__).parent
PAGE_SIZE = 50

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; "
        "base-uri 'none'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


# ------------------------------------------------------------------ formatting
def make_filters(config: Config) -> dict[str, Any]:
    sym = config.currency_symbol

    def money(v: Any, decimals: int = 0) -> str:
        try:
            x = float(v or 0)
        except (TypeError, ValueError):
            return "-"
        return f"{'-' if x < 0 else ''}{sym}{abs(x):,.{decimals}f}"

    def dt(v: Any, fmt: str = "%d %b %Y") -> str:
        d = parse_dt(v)
        return d.strftime(fmt) if d else "—"

    def dtt(v: Any) -> str:
        return dt(v, "%d %b %Y %H:%M")

    def ago(v: Any) -> str:
        d = parse_dt(v)
        if not d:
            return "never"
        days = (utcnow() - d).days
        if days < 0:
            return f"in {-days}d"
        if days == 0:
            return "today"
        if days < 60:
            return f"{days}d ago"
        if days < 730:
            return f"{days // 30}mo ago"
        return f"{days // 365}y ago"

    def days_until(v: Any) -> int | None:
        d = parse_dt(v)
        return None if not d else (d.date() - utcnow().date()).days

    def num(v: Any, decimals: int = 0) -> str:
        try:
            return f"{float(v):,.{decimals}f}"
        except (TypeError, ValueError):
            return "-"

    def pct(v: Any, decimals: int = 0) -> str:
        try:
            return f"{float(v) * 100:.{decimals}f}%"
        except (TypeError, ValueError):
            return "-"

    def tojson_pretty(v: Any) -> str:
        return json.dumps(v, indent=2, default=str, sort_keys=True)

    return {
        "money": money,
        "dt": dt,
        "dtt": dtt,
        "ago": ago,
        "days_until": days_until,
        "num": num,
        "pct": pct,
        "pretty": tojson_pretty,
    }


def _flash(request: Request, level: str, message: str) -> None:
    request.session.setdefault("flash", []).append([level, message])


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


# --------------------------------------------------------------------- factory
def create_app(spec: AppSpec, config: Config | None = None, run_initial_scan: bool = True) -> FastAPI:
    config = config or Config.from_env(spec.slug)
    db = Database(config.database_path)
    db.init(spec.schema_sql)
    ctx = Context(
        spec=spec,
        config=config,
        db=db,
        settings=SettingsStore(db, spec.setting_defs),
        findings=FindingStore(db),
    )
    ctx.scanner = Scanner(ctx)

    env = Environment(
        loader=ChoiceLoader(
            [FileSystemLoader(str(spec.templates_dir)), FileSystemLoader(str(CORE_DIR / "templates"))]
        ),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    filters = make_filters(config)
    env.filters.update(filters)
    env.globals.update({f"fmt_{name}": fn for name, fn in filters.items()})
    env.globals.update(
        spec=spec,
        config=config,
        charts=charts,
        SEVERITIES=SEVERITIES,
        STATUSES=STATUSES,
        STATUS_LABELS=STATUS_LABELS,
        MAX_ACCEPT_DAYS=MAX_ACCEPT_DAYS,
    )
    templates = Jinja2Templates(env=env)
    ctx.templates = templates

    def render(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
        user = current_user(request)
        last_scan = db.one("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
        base = {
            "user": user,
            "is_admin": bool(user and user["role"] == ROLE_ADMIN),
            "csrf": csrf_token(request),
            "flashes": request.session.pop("flash", []),
            "path": request.url.path,
            "last_scan": last_scan,
            "scan_running": ctx.scanner.running,
            "today": utcnow().date().isoformat(),
            "max_accept_date": (utcnow().date() + timedelta(days=MAX_ACCEPT_DAYS)).isoformat(),
            "default_accept_date": (utcnow().date() + timedelta(days=90)).isoformat(),
        }
        base.update(context)
        return templates.TemplateResponse(request, name, base, status_code=status_code)

    ctx.state["render"] = render
    throttle = LoginThrottle()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if spec.on_startup:
            spec.on_startup(ctx)
        if run_initial_scan and config.demo_mode and not db.scalar("SELECT COUNT(*) FROM scans", (), 0):
            log.info("Demo mode: running the first scan so the dashboard has data")
            ctx.scanner.run("startup", "system")
        ctx.scanner.start_schedule(config.scan_interval_hours)
        yield
        ctx.scanner.stop()

    app = FastAPI(
        title=spec.name,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.ctx = ctx
    app.add_middleware(
        SessionMiddleware,
        secret_key=config.secret_key,
        session_cookie=f"{spec.slug}_session",
        max_age=8 * 3600,
        same_site="lax",
        https_only=config.session_cookie_secure,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response: Response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith(("/api/", "/findings", "/report")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.mount("/static", StaticFiles(directory=str(CORE_DIR / "static")), name="static")

    # ------------------------------------------------------- error handlers
    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        return redirect("/login?" + urlencode({"next": safe_next(exc.next_path)}))

    @app.exception_handler(Forbidden)
    async def _forbidden(request: Request, exc: Forbidden):
        return render(request, "error.html", status_code=403, title="Not allowed", message=exc.message)

    @app.exception_handler(ApiUnauthorized)
    async def _api_unauth(request: Request, exc: ApiUnauthorized):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    # ---------------------------------------------------------------- auth
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, next: str = "/"):
        if current_user(request):
            return redirect(safe_next(next))
        return render(request, "login.html", next=safe_next(next), error=None)

    @app.post("/login")
    async def login_submit(request: Request):
        form = await request.form()
        nxt = safe_next(str(form.get("next", "/")))
        key = client_key(request)
        if throttle.blocked(key):
            return render(
                request, "login.html", status_code=429, next=nxt,
                error="Too many failed attempts. Wait a few minutes and try again.",
            )
        if str(form.get("csrf_token", "")) != request.session.get("csrf"):
            return render(request, "login.html", status_code=400, next=nxt, error="Session expired, please try again.")
        username = str(form.get("username", ""))
        role = check_credentials(config, username, str(form.get("password", "")))
        if not role:
            throttle.fail(key)
            db.audit(username[:80] or "?", "auth.failed", "login", key)
            return render(request, "login.html", status_code=401, next=nxt, error="Incorrect username or password.")
        throttle.reset(key)
        login(request, username.strip(), role)
        db.audit(username.strip(), "auth.login", "login", role)
        return redirect(nxt)

    @app.post("/logout")
    async def logout(request: Request):
        user = current_user(request)
        form = await request.form()
        if user and str(form.get("csrf_token", "")) == request.session.get("csrf"):
            db.audit(user["name"], "auth.logout", "login")
            request.session.clear()
        return redirect("/login")

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz():
        db.scalar("SELECT 1")
        return "ok"

    # ----------------------------------------------------------- dashboard
    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request, user=Depends(require_user)):
        scan, _ = ctx.latest()
        data = spec.dashboard(ctx) if scan else {}
        return render(request, "dashboard.html", scan=scan, summary=ctx.findings.summary(), **data)

    # ------------------------------------------------------------ findings
    def _finding_filters(request: Request) -> dict:
        qp = request.query_params
        return {
            "status": qp.get("status", "active"),
            "severity": qp.get("severity", ""),
            "rule_id": qp.get("rule", ""),
            "owner": qp.get("owner", ""),
            "q": qp.get("q", "").strip()[:100],
            "overdue": qp.get("overdue") == "1",
            "sort": qp.get("sort", "severity"),
            "entity_type": qp.get("entity_type", ""),
            "entity_id": qp.get("entity_id", ""),
        }

    @app.get("/findings", response_class=HTMLResponse)
    async def findings_page(request: Request, page: int = 1, user=Depends(require_user)):
        filters = _finding_filters(request)
        page = max(page, 1)
        rows, total = ctx.findings.search(**filters, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE)
        for r in rows:
            r["link"] = spec.entity_link(r)
        qs = {k: v for k, v in request.query_params.items() if k != "page"}
        return render(
            request,
            "findings.html",
            rows=rows,
            total=total,
            page=page,
            pages=max(1, math.ceil(total / PAGE_SIZE)),
            filters=filters,
            qs=urlencode(qs),
            owners=ctx.findings.owners(),
        )

    @app.get("/findings.csv")
    async def findings_csv(request: Request, user=Depends(require_user)):
        filters = _finding_filters(request)
        rows, _ = ctx.findings.search(**filters, limit=100000)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([
            "id", "rule_id", "rule", "severity", "status", "title", "entity_type", "entity_id",
            "entity_name", f"monthly_cost ({config.currency_symbol})", "owner", "due_date",
            "overdue", "first_seen", "last_seen", "accepted_until", "justification", "recommendation",
        ])
        for r in rows:
            rule = spec.rules.get(r["rule_id"])
            w.writerow([
                r["id"], r["rule_id"], rule.title if rule else "", r["severity"], r["status"],
                _csv_safe(r["title"]), r["entity_type"], _csv_safe(r["entity_id"]),
                _csv_safe(r["entity_name"]), f"{r['monthly_cost']:.2f}", _csv_safe(r["owner"] or ""),
                r["due_date"] or "", "yes" if r["overdue"] else "no", r["first_seen"], r["last_seen"],
                r["accepted_until"] or "", _csv_safe(r["justification"] or ""), _csv_safe(r["recommendation"]),
            ])
        db.audit(user["name"], "export.findings_csv", "findings", f"{len(rows)} rows")
        stamp = utcnow().strftime("%Y%m%d")
        return Response(
            buf.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{spec.slug}-findings-{stamp}.csv"'},
        )

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    async def finding_detail(request: Request, finding_id: int, user=Depends(require_user)):
        f = ctx.findings.get(finding_id)
        if not f:
            return render(request, "error.html", status_code=404, title="Not found", message="That finding does not exist.")
        f["link"] = spec.entity_link(f)
        return render(request, "finding_detail.html", f=f, rule=spec.rules.get(f["rule_id"]), owners=ctx.findings.owners())

    @app.post("/findings/{finding_id}/action")
    async def finding_action(request: Request, finding_id: int, form=Depends(require_admin_form)):
        user = current_user(request)
        try:
            ctx.findings.apply(
                finding_id,
                str(form.get("action", "")),
                user["name"],
                owner=str(form.get("owner", "")),
                justification=str(form.get("justification", "")),
                accepted_until=str(form.get("accepted_until", "")),
                comment=str(form.get("comment", "")),
            )
            _flash(request, "success", "Finding updated.")
        except FindingError as exc:
            _flash(request, "error", str(exc))
        return redirect(f"/findings/{finding_id}")

    @app.post("/findings/bulk")
    async def findings_bulk(request: Request, form=Depends(require_admin_form)):
        user = current_user(request)
        ids = [int(i) for i in form.getlist("ids") if str(i).isdigit()][:500]
        action = str(form.get("action", ""))
        ok, errors = 0, []
        for fid in ids:
            try:
                ctx.findings.apply(
                    fid, action, user["name"],
                    owner=str(form.get("owner", "")),
                    justification=str(form.get("justification", "")),
                    accepted_until=str(form.get("accepted_until", "")),
                )
                ok += 1
            except FindingError as exc:
                errors.append(f"#{fid}: {exc}")
        if ok:
            _flash(request, "success", f"Updated {ok} finding(s).")
        if errors:
            _flash(request, "error", "; ".join(errors[:5]) + (" …" if len(errors) > 5 else ""))
        if not ids:
            _flash(request, "error", "Select at least one finding.")
        return redirect(safe_next(str(form.get("back", "/findings"))))

    # --------------------------------------------------------------- scans
    @app.get("/scans", response_class=HTMLResponse)
    async def scans_page(request: Request, user=Depends(require_user)):
        scans = db.query("SELECT * FROM scans ORDER BY id DESC LIMIT 50")
        for s in scans:
            s["stats"] = json.loads(s.pop("stats_json") or "{}")
        missing = [] if config.demo_mode else spec.live_requirements(ctx)
        return render(request, "scans.html", scans=scans, missing=missing)

    @app.post("/scans/run")
    async def scans_run(request: Request, form=Depends(require_admin_form)):
        user = current_user(request)
        try:
            ctx.scanner.run_in_background("manual", user["name"])
            _flash(request, "info", "Scan started. This page refreshes until it finishes.")
        except ScanInProgress as exc:
            _flash(request, "error", str(exc))
        return redirect("/scans")

    @app.get("/connection", response_class=HTMLResponse)
    async def connection_page(request: Request, user=Depends(require_user)):
        missing = spec.live_requirements(ctx)
        return render(request, "connection.html", missing=missing)

    # ------------------------------------------------------------ settings
    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request, user=Depends(require_user)):
        return render(request, "settings.html", values=ctx.settings.all(), groups=ctx.settings.grouped())

    @app.post("/settings")
    async def settings_save(request: Request, form=Depends(require_admin_form)):
        user = current_user(request)
        values: dict[str, Any] = {}
        for key, d in ctx.settings.defs.items():
            if d.hidden:
                continue
            if d.type == "bool":
                values[key] = form.get(key) == "on"
            elif key in form:
                values[key] = form.get(key)
        try:
            changed = ctx.settings.set_many(values, user["name"])
            _flash(request, "success", f"Saved {len(changed)} change(s). Run a scan to apply them." if changed else "No changes.")
        except SettingsError as exc:
            _flash(request, "error", str(exc))
        return redirect("/settings")

    # ------------------------------------------------------- rules & audit
    @app.get("/rules", response_class=HTMLResponse)
    async def rules_page(request: Request, user=Depends(require_user)):
        counts = {r["rule_id"]: r["n"] for r in ctx.findings.summary()["by_rule"]}
        return render(request, "rules.html", rules=list(spec.rules.values()), counts=counts)

    @app.get("/audit", response_class=HTMLResponse)
    async def audit_page(request: Request, page: int = 1, user=Depends(require_user)):
        page = max(page, 1)
        rows = db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", (PAGE_SIZE, (page - 1) * PAGE_SIZE))
        total = db.scalar("SELECT COUNT(*) FROM audit_log", (), 0)
        return render(request, "audit.html", rows=rows, page=page, pages=max(1, math.ceil(total / PAGE_SIZE)))

    @app.get("/report", response_class=HTMLResponse)
    async def report_page(request: Request, user=Depends(require_user)):
        scan, _ = ctx.latest()
        rows, _ = ctx.findings.search(status="active", limit=25)
        db.audit(user["name"], "export.report", "report")
        return render(
            request,
            "report.html",
            scan=scan,
            summary=ctx.findings.summary(),
            top=rows,
            generated=utcnow(),
            extra=spec.report_context(ctx) if scan else {},
        )

    # ----------------------------------------------------------------- API
    @app.get("/api/summary")
    async def api_summary(request: Request, user=Depends(require_api)):
        scan, _ = ctx.latest()
        return {"app": spec.slug, "mode": ctx.mode, "last_scan": scan, "summary": ctx.findings.summary()}

    @app.get("/api/findings")
    async def api_findings(request: Request, limit: int = 500, offset: int = 0, user=Depends(require_api)):
        filters = _finding_filters(request)
        rows, total = ctx.findings.search(**filters, limit=min(max(limit, 1), 5000), offset=max(offset, 0))
        return {"total": total, "items": rows}

    spec.register_routes(app, ctx)
    return app


def _csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection in exported cells."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def page_render(ctx: Context):
    """Helper for product routes: returns the shared render(request, template, **ctx) function."""
    return ctx.state["render"]


def parse_date_field(value: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date().isoformat()
    except ValueError:
        return None
