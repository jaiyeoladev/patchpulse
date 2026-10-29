"""Operating system servicing dates, severity mapping and remediation SLAs.

Servicing dates are taken from Microsoft's published lifecycle for Windows 10/11 feature updates and
Windows Server. They are editable in Settings → "OS lifecycle table" — check
https://learn.microsoft.com/lifecycle for changes and Extended Security Update (ESU) coverage.
"""

from __future__ import annotations

import re

DEFAULT_LIFECYCLE = {
    "windows_client": {
        "19045": {"name": "Windows 10 22H2", "pro": "2025-10-14", "enterprise": "2025-10-14"},
        "22000": {"name": "Windows 11 21H2", "pro": "2023-10-10", "enterprise": "2024-10-08"},
        "22621": {"name": "Windows 11 22H2", "pro": "2024-10-08", "enterprise": "2025-10-14"},
        "22631": {"name": "Windows 11 23H2", "pro": "2025-11-11", "enterprise": "2026-11-10"},
        "26100": {"name": "Windows 11 24H2", "pro": "2026-10-13", "enterprise": "2027-10-12"},
        "26200": {"name": "Windows 11 25H2", "pro": "2027-10-12", "enterprise": "2028-10-10"},
    },
    "windows_server": {
        "2008": "2020-01-14",
        "2012": "2023-10-10",
        "2016": "2027-01-12",
        "2019": "2029-01-09",
        "2022": "2031-10-14",
    },
}

DEFAULT_SLA = {"critical": 14, "high": 14, "medium": 60, "low": 90}

EDR_PLATFORMS_DEFAULT = "Windows\nmacOS\nLinux"


def severity_from_cvss(score: float | None, fallback: str = "medium") -> str:
    if score is None:
        return fallback
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def normalise_severity(text: str | None) -> str | None:
    if not text:
        return None
    t = str(text).strip().lower()
    mapping = {"critical": "critical", "crit": "critical", "high": "high", "important": "high",
               "medium": "medium", "moderate": "medium", "low": "low", "info": "info",
               "informational": "info", "none": "info", "4": "critical", "3": "high", "2": "medium", "1": "low"}
    return mapping.get(t)


def host_key(name: str | None) -> str:
    """Normalise a device name for matching across tools: lowercase, no domain suffix."""
    if not name:
        return ""
    return name.strip().lower().split(".")[0]


def windows_build(os_version: str | None) -> str | None:
    """'10.0.22631.4317' -> '22631'."""
    if not os_version:
        return None
    m = re.match(r"^\s*10\.0\.(\d{5})", os_version)
    return m.group(1) if m else None


def windows_server_release(os_text: str | None) -> str | None:
    if not os_text:
        return None
    m = re.search(r"Server\s*(\d{4})", os_text, re.IGNORECASE)
    return m.group(1) if m else None
