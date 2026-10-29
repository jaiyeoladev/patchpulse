"""PatchPulse application spec and ASGI entry point."""

from __future__ import annotations

from pathlib import Path

from . import views
from .catalog import DEFAULT_LIFECYCLE, EDR_PLATFORMS_DEFAULT
from .collector import GRAPH_PERMISSIONS, collect_live
from .core import AppSpec, Config, NavItem, SettingDef, create_app
from .core.context import Context
from .demo import collect_demo, seed_demo
from .rules import RULES, analyse

SCHEMA = """
CREATE TABLE IF NOT EXISTS imported_vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    hostname TEXT NOT NULL,
    cve TEXT NOT NULL,
    title TEXT,
    cvss REAL,
    severity TEXT,
    first_seen TEXT,
    product TEXT,
    remediation TEXT,
    imported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_imported_source ON imported_vulns(source);
"""

SEVERITY_CHOICES = [("critical", "Critical only"), ("high", "High and above"), ("medium", "Medium and above"),
                    ("low", "Low and above")]

SETTINGS = [
    SettingDef("sla_critical", "Critical (days)", "int", 14, "", "Remediation SLA", 1, 365),
    SettingDef("sla_high", "High (days)", "int", 14,
               "Cyber Essentials requires high-risk and critical updates (CVSS v3 7.0+) within 14 days of release.",
               "Remediation SLA", 1, 365),
    SettingDef("sla_medium", "Medium (days)", "int", 60, "", "Remediation SLA", 1, 365),
    SettingDef("sla_low", "Low (days)", "int", 90, "", "Remediation SLA", 1, 730),
    SettingDef("sla_kev", "CISA Known Exploited (days)", "int", 14,
               "Applied when a CVE is on the CISA KEV catalogue, if shorter than its severity SLA.", "Remediation SLA",
               1, 365),
    SettingDef("kev_is_critical", "Treat every KEV entry as critical", "bool", True, "", "Remediation SLA"),
    SettingDef("kev_enrich", "Enrich with the CISA KEV feed (live mode)", "bool", True,
               "Downloads the public KEV catalogue once a day.", "Remediation SLA"),
    SettingDef("min_vuln_severity", "Track vulnerabilities from", "text", "low", "", "Remediation SLA",
               choices=SEVERITY_CHOICES),
    SettingDef("owner_rules", "Ownership rules", "textarea",
               "server = Infrastructure team\nsrv-sql* = Database team\nplatform:macOS = Desktop support\n"
               "platform:iOS = Mobile team\nfw-* = Network team\n* = Desktop support",
               "One rule per line: pattern = owner. Patterns: a name wildcard (srv-*), 'server', or platform:<name>. "
               "First match wins; applied to new findings without an owner.", "Ownership"),
    SettingDef("stale_sync_days", "Intune check-in overdue after (days)", "int", 14, "", "Device health", 1, 180),
    SettingDef("falcon_stale_days", "Falcon sensor stale after (days)", "int", 7, "", "Device health", 1, 180),
    SettingDef("edr_platforms", "Platforms that must run EDR", "textarea", EDR_PLATFORMS_DEFAULT,
               "One per line (Windows, macOS, Linux, iOS, Android).", "Device health"),
    SettingDef("skip_servers_for_unmanaged", "Do not require Intune for servers", "bool", True, "", "Device health"),
    SettingDef("windows_servicing_track", "Windows edition for servicing dates", "text", "pro",
               "Home/Pro editions get 24 months of updates per Windows 11 release, Enterprise/Education get 36.",
               "OS lifecycle", choices=[("pro", "Home / Pro / Business"), ("enterprise", "Enterprise / Education")]),
    SettingDef("os_eos_warning_days", "Warn before end of support (days)", "int", 90, "", "OS lifecycle", 7, 365),
    SettingDef("os_lifecycle", "OS lifecycle table", "json", DEFAULT_LIFECYCLE,
               "Windows client builds and Windows Server releases with end-of-servicing dates. Verify against "
               "Microsoft's lifecycle pages.", "OS lifecycle"),
]


def live_requirements(ctx: Context) -> list[str]:
    c = ctx.config
    has_graph = c.graph_configured
    has_falcon = bool(c.env("FALCON_CLIENT_ID") and c.env("FALCON_CLIENT_SECRET"))
    has_csv = bool(ctx.db.scalar("SELECT COUNT(*) FROM imported_vulns", (), 0))
    if has_graph or has_falcon or has_csv:
        return []
    return ["AZURE_* (Intune) and/or FALCON_CLIENT_ID + FALCON_CLIENT_SECRET, or a CSV import"]


def on_startup(ctx: Context) -> None:
    if ctx.config.demo_mode:
        seed_demo(ctx)


SPEC = AppSpec(
    slug="patchpulse",
    name="PatchPulse",
    tagline="Endpoint compliance, EDR coverage and vulnerability SLA tracking",
    description="Joins Intune, CrowdStrike Falcon and scanner exports to show what is unpatched, unprotected or "
                "unsupported, who owns it and whether it is inside SLA.",
    package_dir=Path(__file__).parent,
    nav=[NavItem("Devices", "/devices"), NavItem("Vulnerabilities", "/vulnerabilities"), NavItem("Owners", "/owners"),
         NavItem("Import", "/import")],
    rules=RULES,
    setting_defs=SETTINGS,
    collect_demo=collect_demo,
    collect_live=collect_live,
    analyse=analyse,
    dashboard=views.dashboard,
    register_routes=views.register_routes,
    live_requirements=live_requirements,
    schema_sql=SCHEMA,
    entity_link=views.entity_link,
    report_context=views.report_context,
    on_startup=on_startup,
    graph_permissions=GRAPH_PERMISSIONS,
)


def build(config: Config | None = None, run_initial_scan: bool = True):
    return create_app(SPEC, config or Config.from_env(SPEC.slug), run_initial_scan=run_initial_scan)


def __getattr__(name: str):
    if name == "app":
        global app
        app = build()
        return app
    raise AttributeError(name)
