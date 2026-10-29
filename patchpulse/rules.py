"""Endpoint compliance, EDR coverage and vulnerability SLA rules."""

from __future__ import annotations

from datetime import timedelta
from fnmatch import fnmatch
from typing import Any

from .catalog import DEFAULT_LIFECYCLE, severity_from_cvss, windows_server_release
from .core.db import parse_dt, utcnow
from .core.findings import SEVERITY_RANK, Finding, RuleInfo, due_from

RULES = {r.rule_id: r for r in [
    RuleInfo("EPC-001", "Device not compliant in Intune", "high", "Compliance",
             "Intune reports the device as non-compliant, in conflict or in error against its compliance policies."),
    RuleInfo("EPC-002", "Device has not checked in to Intune", "medium", "Compliance",
             "The device has not synced with Intune for longer than the threshold, so its policy, patch and "
             "compliance state are unknown."),
    RuleInfo("EPC-003", "Disk not encrypted", "high", "Compliance",
             "Intune reports that the device disk is not encrypted (BitLocker/FileVault). A lost device exposes its data."),
    RuleInfo("EPC-004", "Operating system out of support", "high", "Lifecycle",
             "The OS version no longer receives security updates. Cyber Essentials requires in-scope devices to "
             "run supported, licensed software.", "NCSC Cyber Essentials: security update management"),
    RuleInfo("EPC-005", "Operating system support ends soon", "medium", "Lifecycle",
             "The OS version stops receiving security updates within the warning window."),
    RuleInfo("EPC-006", "No EDR sensor", "high", "EDR coverage",
             "The device is managed by Intune but has no CrowdStrike Falcon sensor, so attacks on it would not be "
             "detected or contained."),
    RuleInfo("EPC-007", "Device not managed by Intune", "medium", "EDR coverage",
             "The Falcon sensor sees this device but Intune does not manage it, so compliance and patch policy are "
             "not enforced. Common for kiosks, shared PCs and personal devices."),
    RuleInfo("EPC-008", "EDR sensor not reporting or degraded", "high", "EDR coverage",
             "The Falcon sensor has not reported for longer than the threshold or is in Reduced Functionality Mode."),
    RuleInfo("EPC-009", "Jailbroken or rooted mobile device", "critical", "Compliance",
             "Intune reports the device as jailbroken or rooted, which bypasses platform security controls."),
    RuleInfo("VUL-001", "Open vulnerability", "high", "Vulnerabilities",
             "A vulnerability scanner reports an unpatched CVE on the device. The due date comes from your SLA "
             "(default: critical and high-risk CVSS ≥ 7 within 14 days, as Cyber Essentials requires; CISA KEV "
             "entries use the KEV SLA).", "NCSC Cyber Essentials requirements: apply high-risk/critical updates within 14 days"),
]}


def owner_for(device: dict, rules_text: str) -> str | None:
    """Owner rules, one per line: '<pattern> = <owner>'. Pattern may be 'platform:macOS', 'server', or a name glob."""
    name = (device.get("name") or "").lower()
    for line in (rules_text or "").splitlines():
        if "=" not in line:
            continue
        pattern, _, owner = (x.strip() for x in line.partition("="))
        if not pattern or not owner:
            continue
        pl = pattern.lower()
        if pl.startswith("platform:"):
            if device.get("platform", "").lower() == pl.split(":", 1)[1].strip():
                return owner
        elif pl == "server":
            if device.get("server"):
                return owner
        elif fnmatch(name, pl):
            return owner
    return None


def os_status(device: dict, lifecycle: dict, track: str) -> tuple[str | None, str, str | None]:
    """Returns (end_of_support_date, os_label, None)."""
    if device.get("platform") == "Windows" and not device.get("server"):
        build = device.get("build")
        table = (lifecycle or DEFAULT_LIFECYCLE).get("windows_client", {})
        if build and build in table:
            entry = table[build]
            return entry.get(track) or entry.get("pro"), entry.get("name", build), None
        if build and build.startswith("1") and int(build) < 19045:
            return "2025-10-14", f"Windows 10 (build {build})", None
        falcon_os = (device.get("falcon") or {}).get("os", "")
        if not build and falcon_os.startswith("Windows 10"):
            return "2025-10-14", "Windows 10", None
    os_text = (device.get("falcon") or {}).get("os") or device.get("os") or ""
    release = windows_server_release(os_text)
    if release:
        table = (lifecycle or DEFAULT_LIFECYCLE).get("windows_server", {})
        if release in table:
            return table[release], os_text, None
    return None, os_text, None


def sla_days(severity: str, kev: bool, settings: dict) -> int:
    days = int(settings[f"sla_{severity}"]) if severity in ("critical", "high", "medium", "low") else 0
    if kev:
        days = min(days or 10**6, int(settings["sla_kev"]))
    return days


def analyse(data: dict, settings: dict[str, Any], ctx=None) -> list[Finding]:
    now = utcnow()
    out: list[Finding] = []
    sources = data.get("sources", {})
    lifecycle = settings["os_lifecycle"] or DEFAULT_LIFECYCLE
    track = settings["windows_servicing_track"]
    warn_days = int(settings["os_eos_warning_days"])
    edr_platforms = {p.strip().lower() for p in (settings["edr_platforms"] or "").splitlines() if p.strip()}
    owner_rules = settings["owner_rules"] or ""
    min_sev = settings["min_vuln_severity"]
    by_key = {d["key"]: d for d in data.get("devices", [])}

    for d in data.get("devices", []):
        name, key = d["name"], d["key"]
        intune, falcon = d.get("intune"), d.get("falcon")
        owner = owner_for(d, owner_rules)
        base = {"platform": d.get("platform"), "os": d.get("osVersion") or d.get("os"), "user": d.get("user") or "—"}
        d["owner"] = owner

        def add(rule, sev, title, details, rec, k=""):
            out.append(Finding(rule, sev, title, "device", key, name, {**base, **details}, rec, owner_hint=owner, key=k))

        if intune:
            state = (intune.get("complianceState") or "").lower()
            if state in ("noncompliant", "conflict", "error"):
                add("EPC-001", "high", f"Intune compliance state: {state}", {"compliance_state": state},
                    "Open the device in Intune to see which policy fails, fix it (often a pending update, BitLocker "
                    "or firewall setting) and sync the device.")
            last = parse_dt(intune.get("lastSync"))
            if last and (now - last).days > int(settings["stale_sync_days"]):
                add("EPC-002", "medium", f"No Intune check-in for {(now - last).days} days",
                    {"last_sync": intune.get("lastSync")},
                    "Contact the user to power on and connect the device. If it is lost or retired, wipe and retire "
                    "it in Intune and remove it from Entra ID.")
            if intune.get("encrypted") is False and d.get("platform") in ("Windows", "macOS"):
                add("EPC-003", "high", "Disk not encrypted", {"encrypted": False},
                    "Assign the BitLocker (Windows) or FileVault (macOS) policy and confirm the recovery key is escrowed.")
            if str(intune.get("jailBroken", "")).lower() == "true":
                add("EPC-009", "critical", "Device is jailbroken or rooted", {"jailbroken": True},
                    "Block access with a compliance policy and Conditional Access, then retire the device.")

        eos, os_label, _ = os_status(d, lifecycle, track)
        eos_dt = parse_dt(eos)
        if eos_dt:
            if eos_dt < now:
                add("EPC-004", "high", f"{os_label} out of support since {eos_dt.date().isoformat()}",
                    {"os_release": os_label, "end_of_support": eos_dt.date().isoformat(), "servicing_track": track},
                    "Upgrade to a supported release (or enrol in Extended Security Updates where available). "
                    "Unsupported devices must be removed from Cyber Essentials scope or segregated.")
            elif eos_dt < now + timedelta(days=warn_days):
                add("EPC-005", "medium", f"{os_label} support ends {eos_dt.date().isoformat()}",
                    {"os_release": os_label, "end_of_support": eos_dt.date().isoformat(), "servicing_track": track},
                    "Schedule the feature update (Windows Update for Business / Autopatch ring) before the end date.")

        edr_eligible = d.get("platform", "").lower() in edr_platforms
        if sources.get("falcon"):
            if intune and not falcon and edr_eligible:
                add("EPC-006", "high", "No CrowdStrike Falcon sensor", {"intune_id": intune.get("id")},
                    "Deploy the Falcon sensor through Intune (Win32 app or macOS package) with the correct CID and "
                    "confirm it appears in the Falcon console.")
            if falcon:
                seen = parse_dt(falcon.get("lastSeen"))
                if seen and (now - seen).days > int(settings["falcon_stale_days"]):
                    add("EPC-008", "high", f"Falcon sensor last seen {(now - seen).days} days ago",
                        {"last_seen": falcon.get("lastSeen"), "agent_version": falcon.get("agentVersion")},
                        "Check whether the device is still in use. If it is, repair or reinstall the sensor.", k="stale")
                if falcon.get("rfm"):
                    add("EPC-008", "high", "Falcon sensor in Reduced Functionality Mode",
                        {"agent_version": falcon.get("agentVersion")},
                        "Update the sensor to a version that supports the installed OS kernel/build.", k="rfm")
        if sources.get("intune") and falcon and not intune and edr_eligible and not d.get("scanner_only"):
            if not (settings["skip_servers_for_unmanaged"] and d.get("server")):
                add("EPC-007", "medium", "Seen by Falcon but not managed by Intune",
                    {"falcon_os": falcon.get("os"), "product_type": falcon.get("productType")},
                    "Enrol the device in Intune (or co-management), or document why it is out of scope.")

    # ----------------------------------------------------------- vulnerabilities
    existing_first: dict[str, str] = {}
    if ctx is not None:
        for r in ctx.db.query("SELECT fingerprint, first_seen FROM findings WHERE rule_id = 'VUL-001'"):
            existing_first[r["fingerprint"]] = r["first_seen"]
    floor = SEVERITY_RANK.get(min_sev, SEVERITY_RANK["low"])
    for v in data.get("vulns", []):
        sev = v.get("severity") or severity_from_cvss(v.get("cvss"))
        if v.get("kev") and SEVERITY_RANK[sev] > SEVERITY_RANK["high"]:
            sev = "high"
        if v.get("kev") and settings["kev_is_critical"]:
            sev = "critical"
        if SEVERITY_RANK.get(sev, 9) > floor:
            continue
        device = by_key.get(v["host_key"], {"name": v["hostname"], "key": v["host_key"]})
        owner = device.get("owner") or owner_for(device, owner_rules)
        f = Finding(
            "VUL-001", sev, f"{v['cve']}{' (CISA KEV)' if v.get('kev') else ''}: {v.get('title') or ''}"[:200],
            "device", v["host_key"], device.get("name") or v["hostname"],
            {"cve": v["cve"], "cvss": v.get("cvss"), "kev": bool(v.get("kev")), "exprt_rating": v.get("exprt") or "—",
             "product": v.get("product") or "—", "source": v.get("source"),
             "detected": v.get("first_seen")},
            v.get("remediation") or "Apply the vendor update for the affected product.",
            owner_hint=owner, key=v["cve"],
        )
        start = parse_dt(v.get("first_seen"))
        prev = parse_dt(existing_first.get(f.fingerprint))
        if prev and (not start or prev < start):
            start = prev
        f.first_seen = start.isoformat().replace("+00:00", "Z") if start else None
        f.due_date = due_from(start or now, sla_days(sev, bool(v.get("kev")), settings))
        out.append(f)
    return out
