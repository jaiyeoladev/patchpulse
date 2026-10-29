"""Runs a collection + analysis cycle and records the result."""

from __future__ import annotations

import json
import logging
import threading
import time
import traceback

from .context import Context
from .db import iso, utcnow
from .graph import GraphError

log = logging.getLogger(__name__)


class ScanInProgress(RuntimeError):
    pass


class Scanner:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._lock.locked()

    def run(self, trigger: str = "manual", actor: str = "system") -> int:
        if not self._lock.acquire(blocking=False):
            raise ScanInProgress("A scan is already running.")
        ctx = self.ctx
        db = ctx.db
        started = time.monotonic()
        scan_id = db.execute(
            "INSERT INTO scans (started_at, mode, trigger, actor, status) VALUES (?, ?, ?, ?, 'running')",
            (iso(utcnow()), ctx.mode, trigger, actor),
        )
        try:
            if ctx.config.demo_mode:
                dataset = ctx.spec.collect_demo(ctx)
            else:
                missing = ctx.spec.live_requirements(ctx)
                if missing:
                    raise RuntimeError("Live mode is missing configuration: " + ", ".join(missing))
                dataset = ctx.spec.collect_live(ctx)
            settings = ctx.settings.all()
            findings = ctx.spec.analyse(dataset, settings, ctx)
            stats = ctx.findings.sync(scan_id, findings)
            stats["findings"] = len(findings)
            stats["warnings"] = dataset.get("warnings", [])
            stats["counts"] = dataset.get("counts", {})
            stats["duration_s"] = round(time.monotonic() - started, 2)
            db.save_dataset(scan_id, dataset)
            db.execute(
                "UPDATE scans SET status='success', finished_at=?, stats_json=? WHERE id=?",
                (iso(utcnow()), json.dumps(stats, default=str), scan_id),
            )
            db.audit(actor, "scan.success", f"scan:{scan_id}", f"{len(findings)} findings ({trigger})")
            log.info("Scan %s finished: %s", scan_id, stats)
        except Exception as exc:  # noqa: BLE001 - record any failure on the scan row
            if isinstance(exc, GraphError):
                message = str(exc)
                if exc.status == 403:
                    message += " - check the app registration has admin-consented permissions."
            else:
                message = f"{type(exc).__name__}: {exc}"
            log.error("Scan %s failed: %s\n%s", scan_id, message, traceback.format_exc())
            db.execute(
                "UPDATE scans SET status='failed', finished_at=?, error=? WHERE id=?",
                (iso(utcnow()), message[:2000], scan_id),
            )
            db.audit(actor, "scan.failed", f"scan:{scan_id}", message[:500])
        finally:
            self._lock.release()
        return scan_id

    def run_in_background(self, trigger: str, actor: str) -> None:
        if self.running:
            raise ScanInProgress("A scan is already running.")
        threading.Thread(target=self._safe_run, args=(trigger, actor), daemon=True).start()

    def _safe_run(self, trigger: str, actor: str) -> None:
        try:
            self.run(trigger, actor)
        except ScanInProgress:
            pass

    # ------------------------------------------------------------ schedule
    def start_schedule(self, hours: float) -> None:
        if hours <= 0 or self._thread:
            return
        interval = max(hours, 0.25) * 3600

        def loop() -> None:
            while not self._stop.wait(interval):
                self._safe_run("schedule", "scheduler")

        self._thread = threading.Thread(target=loop, daemon=True, name="scan-scheduler")
        self._thread.start()
        log.info("Scheduled scans every %.2f hours", hours)

    def stop(self) -> None:
        self._stop.set()
