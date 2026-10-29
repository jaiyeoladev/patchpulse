"""Collects device and vulnerability data from Intune, CrowdStrike Falcon and CSV imports."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from .catalog import host_key, normalise_severity, severity_from_cvss, windows_build
from .core.context import Context
from .core.db import iso, parse_dt, utcnow
from .core.graph import GraphClient, GraphError, graph_client_from_config
from .falcon import FalconClient, FalconError

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GRAPH_PERMISSIONS = ["DeviceManagementManagedDevices.Read.All"]
INTUNE_FIELDS = (
    "id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,isEncrypted,userPrincipalName,"
    "managedDeviceOwnerType,model,manufacturer,serialNumber,azureADDeviceId,jailBroken,enrolledDateTime"
)


def _platform(text: str | None) -> str:
    t = (text or "").lower()
    if "windows" in t or t == "win":
        return "Windows"
    if "mac" in t:
        return "macOS"
    if "ios" in t or "ipad" in t:
        return "iOS"
    if "android" in t:
        return "Android"
    if "linux" in t:
        return "Linux"
    return text or "Unknown"


def normalise_intune(d: dict) -> dict:
    return {
        "key": host_key(d.get("deviceName")),
        "name": d.get("deviceName") or d.get("id"),
        "platform": _platform(d.get("operatingSystem")),
        "os": d.get("operatingSystem") or "",
        "osVersion": d.get("osVersion") or "",
        "build": windows_build(d.get("osVersion")),
        "server": False,
        "user": d.get("userPrincipalName") or "",
        "model": " ".join(filter(None, [d.get("manufacturer"), d.get("model")])),
        "serial": d.get("serialNumber") or "",
        "intune": {
            "id": d.get("id"),
            "complianceState": (d.get("complianceState") or "unknown"),
            "lastSync": iso(parse_dt(d.get("lastSyncDateTime"))),
            "encrypted": d.get("isEncrypted"),
            "jailBroken": str(d.get("jailBroken") or "Unknown"),
            "ownerType": d.get("managedDeviceOwnerType") or "",
            "enrolled": iso(parse_dt(d.get("enrolledDateTime"))),
        },
        "falcon": None,
    }


def normalise_falcon_host(h: dict) -> dict:
    product = h.get("product_type_desc") or ""
    os_text = h.get("os_product_name") or h.get("os_version") or ""
    return {
        "aid": h.get("device_id"),
        "hostname": h.get("hostname") or h.get("device_id"),
        "platform": _platform(h.get("platform_name")),
        "os": os_text,
        "lastSeen": iso(parse_dt(h.get("last_seen"))),
        "agentVersion": h.get("agent_version") or "",
        "rfm": str(h.get("reduced_functionality_mode", "")).lower() == "yes",
        "status": h.get("status") or "normal",
        "productType": product,
        "server": product.lower() in ("server", "domain controller"),
    }


def normalise_spotlight(v: dict) -> dict | None:
    cve = v.get("cve") or {}
    host = v.get("host_info") or {}
    cve_id = cve.get("id")
    hostname = host.get("hostname")
    if not cve_id or not hostname:
        return None
    score = cve.get("base_score")
    try:
        score = float(score) if score is not None else None
    except (TypeError, ValueError):
        score = None
    cisa = cve.get("cisa_info") or {}
    remediation = ((v.get("remediation") or {}).get("entities") or [{}])[0]
    apps = v.get("apps") or [{}]
    return {
        "host_key": host_key(hostname),
        "hostname": hostname,
        "cve": cve_id.upper(),
        "title": (cve.get("description") or "")[:240] or cve_id,
        "cvss": score,
        "severity": normalise_severity(cve.get("severity")) or severity_from_cvss(score),
        "exprt": cve.get("exprt_rating") or "",
        "kev": bool(cisa.get("is_cisa_kev") or cve.get("is_cisa_kev")),
        "first_seen": iso(parse_dt(v.get("created_timestamp"))),
        "product": apps[0].get("product_name_version") or "",
        "remediation": remediation.get("title") or remediation.get("action") or "",
        "source": "CrowdStrike Spotlight",
    }


def merge_devices(intune: list[dict], falcon_hosts: list[dict]) -> list[dict]:
    devices: dict[str, dict] = {}
    for d in intune:
        key = d["key"] or d["intune"]["id"]
        existing = devices.get(key)
        # keep the most recently synced record when a name is reused
        if existing and (existing["intune"]["lastSync"] or "") >= (d["intune"]["lastSync"] or ""):
            continue
        devices[key] = d
    for h in falcon_hosts:
        key = host_key(h["hostname"])
        if key in devices:
            prev = devices[key].get("falcon")
            if not prev or (prev.get("lastSeen") or "") < (h.get("lastSeen") or ""):
                devices[key]["falcon"] = h
            devices[key]["server"] = devices[key]["server"] or h["server"]
        else:
            devices[key] = {
                "key": key, "name": h["hostname"], "platform": h["platform"], "os": h["os"],
                "osVersion": h["os"], "build": None, "server": h["server"], "user": "", "model": "",
                "serial": "", "intune": None, "falcon": h,
            }
    return sorted(devices.values(), key=lambda d: d["name"].lower())


def load_kev(ctx: Context, warnings: list[str]) -> set[str]:
    cache = Path(ctx.config.database_path).with_name("kev-cache.json")
    cached: dict[str, Any] = {}
    if cache.is_file():
        try:
            cached = json.loads(cache.read_text())
        except (OSError, ValueError):
            cached = {}
    fresh = parse_dt(cached.get("fetched"))
    if fresh and (utcnow() - fresh).total_seconds() < 86400:
        return set(cached.get("cves", []))
    try:
        r = httpx.get(KEV_URL, timeout=30, headers={"User-Agent": "patchpulse/1.0"})
        r.raise_for_status()
        cves = sorted({v["cveID"].upper() for v in r.json().get("vulnerabilities", []) if v.get("cveID")})
        cache.write_text(json.dumps({"fetched": iso(utcnow()), "cves": cves}))
        return set(cves)
    except (httpx.HTTPError, ValueError, KeyError, OSError) as exc:
        if cached.get("cves"):
            warnings.append(f"CISA KEV feed unreachable ({type(exc).__name__}); using cached list from {cached.get('fetched')}.")
            return set(cached["cves"])
        warnings.append(f"CISA KEV feed unreachable ({type(exc).__name__}); KEV enrichment skipped.")
        return set()


def imported_vulns(ctx: Context) -> list[dict]:
    rows = ctx.db.query("SELECT * FROM imported_vulns")
    return [{
        "host_key": host_key(r["hostname"]), "hostname": r["hostname"], "cve": r["cve"], "title": r["title"] or r["cve"],
        "cvss": r["cvss"], "severity": r["severity"], "exprt": "", "kev": False,
        "first_seen": r["first_seen"] or r["imported_at"], "product": r["product"] or "",
        "remediation": r["remediation"] or "", "source": r["source"],
    } for r in rows]


def finalise(ctx: Context, devices: list[dict], vulns: list[dict], warnings: list[str], kev: set[str],
             sources: dict) -> dict:
    vulns = vulns + imported_vulns(ctx)
    for v in vulns:
        if v["cve"] in kev:
            v["kev"] = True
    known = {d["key"] for d in devices}
    for v in vulns:
        if v["host_key"] and v["host_key"] not in known:
            devices.append({"key": v["host_key"], "name": v["hostname"], "platform": "Unknown", "os": "",
                            "osVersion": "", "build": None, "server": False, "user": "", "model": "", "serial": "",
                            "intune": None, "falcon": None, "scanner_only": True})
            known.add(v["host_key"])
    sources["csv_rows"] = ctx.db.scalar("SELECT COUNT(*) FROM imported_vulns", (), 0)
    return {
        "devices": devices,
        "vulns": vulns,
        "sources": sources,
        "warnings": warnings,
        "counts": {"devices": len(devices), "vulnerability_instances": len(vulns),
                   "kev_instances": sum(1 for v in vulns if v["kev"])},
    }


def collect_live(ctx: Context, graph: GraphClient | None = None, falcon: FalconClient | None = None) -> dict:
    warnings: list[str] = []
    cfg = ctx.config
    sources = {"intune": False, "falcon": False}
    intune: list[dict] = []
    hosts: list[dict] = []
    vulns: list[dict] = []
    if cfg.graph_configured or graph:
        own = graph is None
        graph = graph or graph_client_from_config(cfg)
        try:
            raw = graph.get_all("deviceManagement/managedDevices", params={"$select": INTUNE_FIELDS, "$top": "1000"})
            intune = [normalise_intune(d) for d in raw]
            sources["intune"] = True
        except GraphError as exc:
            warnings.append(f"Intune devices unavailable: {exc}")
        finally:
            if own:
                graph.close()
    fid, fsecret = cfg.env("FALCON_CLIENT_ID"), cfg.env("FALCON_CLIENT_SECRET")
    if (fid and fsecret) or falcon:
        own = falcon is None
        falcon = falcon or FalconClient(fid, fsecret, cfg.env("FALCON_BASE_URL", "us-1") or "us-1")
        try:
            hosts = [normalise_falcon_host(h) for h in falcon.hosts()]
            sources["falcon"] = True
            vulns = [v for v in (normalise_spotlight(x) for x in falcon.vulnerabilities()) if v]
            sources["spotlight"] = True
        except FalconError as exc:
            warnings.append(f"CrowdStrike Falcon: {exc}")
        finally:
            if own:
                falcon.close()
    if not sources["intune"] and not sources["falcon"] and not ctx.db.scalar("SELECT COUNT(*) FROM imported_vulns", (), 0):
        raise RuntimeError("No data source returned data. Configure Intune (Graph) and/or Falcon, or import a CSV.")
    kev = load_kev(ctx, warnings) if ctx.settings.get("kev_enrich") else set()
    return finalise(ctx, merge_devices(intune, hosts), vulns, warnings, kev, sources)
