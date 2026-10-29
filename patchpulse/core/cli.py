"""Command line: `python -m <package> serve|scan|check`."""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import sys

from .config import Config
from .context import Context
from .db import Database
from .findings import FindingStore
from .graph import GraphError, graph_client_from_config
from .scanner import Scanner
from .settings import SettingsStore
from .spec import AppSpec


def _context(spec: AppSpec, config: Config) -> Context:
    db = Database(config.database_path)
    db.init(spec.schema_sql)
    ctx = Context(spec=spec, config=config, db=db, settings=SettingsStore(db, spec.setting_defs),
                  findings=FindingStore(db))
    ctx.scanner = Scanner(ctx)
    if spec.on_startup:
        spec.on_startup(ctx)
    return ctx


def main(spec: AppSpec, argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=spec.slug, description=f"{spec.name} — {spec.tagline}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve", help="run the web application")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    sub.add_parser("scan", help="run one scan and print a JSON summary (for cron/CI)")
    sub.add_parser("check", help="validate configuration and Microsoft Graph credentials")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.cmd == "serve":
        import uvicorn

        uvicorn.run(f"{spec.slug}.app:build", factory=True, host=args.host, port=args.port,
                    reload=args.reload, proxy_headers=True)
        return 0

    config = Config.from_env(spec.slug)
    ctx = _context(spec, config)

    if args.cmd == "scan":
        scan_id = ctx.scanner.run("cli", "cli")
        row = ctx.db.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row["stats"] = json.loads(row.pop("stats_json") or "{}")
        print(json.dumps({"scan": row, "summary": ctx.findings.summary()}, indent=2, default=str))
        return 0 if row["status"] == "success" else 1

    # check
    print(f"Mode: {'demo' if config.demo_mode else 'live'}")
    print(f"Database: {config.database_path}")
    missing = spec.live_requirements(ctx)
    if missing:
        print("Live mode is missing: " + ", ".join(missing))
        return 0 if config.demo_mode else 1
    if config.graph_configured:
        try:
            with graph_client_from_config(config) as client:
                client.token()
                org = client.get("organization", params={"$select": "displayName"})
                name = (org.get("value") or [{}])[0].get("displayName", "?")
            print(f"Microsoft Graph: OK (tenant: {name})")
        except GraphError as exc:
            print(f"Microsoft Graph: FAILED - {exc}")
            return 1
    print("Configuration OK")
    return 0


def entrypoint() -> None:
    """Console-script entry point (`licenselens`, `agentwarden`, `patchpulse`)."""
    package = __package__.rsplit(".", 1)[0]
    spec = importlib.import_module(f"{package}.app").SPEC
    sys.exit(main(spec))
