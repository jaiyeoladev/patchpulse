"""Synthetic endpoint estate in Intune and CrowdStrike API response shapes."""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import timedelta

from .collector import finalise, merge_devices, normalise_falcon_host, normalise_intune, normalise_spotlight
from .core.context import Context
from .core.db import iso, utcnow

DOMAIN = "northwindcare.example"

# Demo vulnerability catalogue: (cve, cvss, kev, product, short description, remediation, platform)
CVES = [
    ("CVE-2023-4863", 8.8, True, "Google Chrome", "Heap buffer overflow in the WebP image library", "Update Chrome", "Windows"),
    ("CVE-2023-5217", 8.8, True, "Microsoft Edge", "Heap buffer overflow in the VP8 encoder (libvpx)", "Update Edge", "Windows"),
    ("CVE-2024-21412", 8.1, True, "Windows", "Internet Shortcut files security feature bypass", "Install the latest Windows cumulative update", "Windows"),
    ("CVE-2024-38112", 7.5, True, "Windows", "MSHTML platform spoofing", "Install the latest Windows cumulative update", "Windows"),
    ("CVE-2024-38063", 9.8, False, "Windows", "TCP/IP remote code execution via IPv6", "Install the latest Windows cumulative update", "Windows"),
    ("CVE-2024-43491", 9.8, True, "Windows", "Servicing stack remote code execution", "Install the servicing stack and cumulative update", "Windows"),
    ("CVE-2023-38831", 7.8, True, "WinRAR 6.x", "Code execution when opening crafted archives", "Update WinRAR to 6.23 or later, or remove it", "Windows"),
    ("CVE-2024-0727", 5.5, False, "OpenSSL", "NULL pointer dereference processing PKCS12 files", "Update the application bundling OpenSSL", "Windows"),
    ("CVE-2023-48795", 5.9, False, "OpenSSH", "SSH prefix truncation (Terrapin)", "Update the SSH client/server", "Linux"),
    ("CVE-2024-6387", 8.1, False, "OpenSSH server", "Signal handler race condition in sshd", "Update OpenSSH server", "Linux"),
    ("CVE-2021-44228", 10.0, True, "Apache Log4j 2", "Remote code execution via JNDI lookups (Log4Shell)", "Upgrade Log4j to 2.17.1 or later", "Linux"),
    ("CVE-2023-44487", 7.5, True, "HTTP/2 web server", "HTTP/2 rapid reset denial of service", "Apply vendor patch for the web server", "Linux"),
    ("CVE-2024-4577", 9.8, True, "PHP (CGI mode)", "Argument injection in PHP-CGI on Windows", "Upgrade PHP to a fixed release", "Windows"),
]


def _hid(name: str) -> str:
    return hashlib.md5(name.encode(), usedforsecurity=False).hexdigest()


def build_raw(seed: int = 11) -> tuple[list[dict], list[dict], list[dict]]:
    rng = random.Random(seed)
    now = utcnow()
    intune: list[dict] = []
    falcon: list[dict] = []
    users = [f"user{n:03d}@{DOMAIN}" for n in range(1, 200)]

    def intune_dev(name, os_name, os_ver, *, compliant="compliant", sync_days=0, encrypted=True, jail="False"):
        intune.append({
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"intune/{name}")), "deviceName": name, "operatingSystem": os_name,
            "osVersion": os_ver, "complianceState": compliant, "lastSyncDateTime": iso(now - timedelta(days=sync_days, hours=rng.randint(0, 9))),
            "isEncrypted": encrypted, "userPrincipalName": rng.choice(users), "managedDeviceOwnerType": "company",
            "model": "Latitude 5440" if os_name == "Windows" else ("MacBook Air" if os_name == "macOS" else "iPhone 14"),
            "manufacturer": "Dell" if os_name == "Windows" else "Apple", "serialNumber": _hid(name)[:10].upper(),
            "azureADDeviceId": str(uuid.uuid5(uuid.NAMESPACE_URL, f"aad/{name}")), "jailBroken": jail,
            "enrolledDateTime": iso(now - timedelta(days=rng.randint(60, 900))),
        })

    def falcon_host(name, platform, os_text, product="Workstation", seen_days=0, rfm="no"):
        falcon.append({
            "device_id": _hid(name), "hostname": name, "platform_name": platform, "os_product_name": os_text,
            "os_version": os_text, "last_seen": iso(now - timedelta(days=seen_days, minutes=rng.randint(1, 600))),
            "agent_version": rng.choice(["7.18.18909.0", "7.19.19003.0", "7.20.19104.0"]),
            "reduced_functionality_mode": rfm, "status": "normal", "product_type_desc": product,
        })

    builds = ["10.0.26200.6899"] * 16 + ["10.0.26100.6584"] * 2 + ["10.0.22631.5909"]
    for n in range(1, 111):
        name = f"NWC-LT-{n:04d}"
        ver = rng.choice(builds)
        if n <= 12:
            ver = "10.0.19045.6332"  # Windows 10 22H2, past end of support
        compliant = "noncompliant" if n in (14, 33, 57, 72, 88, 101) else "compliant"
        sync = 0 if n not in (21, 44, 66, 93, 108) else rng.randint(16, 60)
        intune_dev(name, "Windows", ver, compliant=compliant, sync_days=sync, encrypted=n not in (37, 81, 99))
        if n in (8, 29, 47, 64, 77, 95, 104):  # no EDR sensor installed
            continue
        win = "Windows 10" if ver.startswith("10.0.19") else "Windows 11"
        seen = 0 if n not in (52, 71) else rng.randint(9, 30)
        falcon_host(name, "Windows", win, seen_days=seen, rfm="yes" if n == 18 else "no")
    for n in range(1, 13):
        name = f"NWC-MB-{n:03d}"
        intune_dev(name, "macOS", rng.choice(["15.6.1", "15.7", "14.7.8"]), encrypted=n != 6)
        if n != 9:
            falcon_host(name, "Mac", "macOS Sequoia")
    for n in range(1, 16):
        name = f"NWC-IP-{n:03d}"
        intune_dev(name, "iOS", rng.choice(["18.6.2", "26.0.1"]), jail="True" if n == 4 else "False",
                   compliant="noncompliant" if n == 4 else "compliant")
    servers = (
        [(f"srv-dc0{i}", "Windows Server 2022", "Domain Controller") for i in (1, 2)]
        + [(f"srv-sql0{i}", "Windows Server 2019", "Server") for i in (1, 2, 3)]
        + [(f"srv-file0{i}", "Windows Server 2016", "Server") for i in (1, 2)]
        + [(f"srv-app{i:02d}", "Windows Server 2022", "Server") for i in range(1, 9)]
        + [(f"srv-rds0{i}", "Windows Server 2022", "Server") for i in range(1, 5)]
        + [("srv-legacy01", "Windows Server 2012 R2", "Server"), ("srv-print01", "Windows Server 2016", "Server")]
        + [(f"lnx-web0{i}", "Ubuntu 22.04", "Server") for i in range(1, 5)]
        + [("lnx-jenkins01", "Ubuntu 20.04", "Server"), ("lnx-elk01", "RHEL 8.10", "Server")]
    )
    for name, os_text, product in servers:
        platform = "Linux" if name.startswith("lnx") else "Windows"
        falcon_host(name, platform, os_text, product=product, seen_days=0 if name != "srv-print01" else 12)
    # one unmanaged workstation seen only by Falcon
    falcon_host("NWC-DESK-KIOSK", "Windows", "Windows 11")

    # Spotlight vulnerabilities
    vulns: list[dict] = []
    win_hosts = [h for h in falcon if h["platform_name"] == "Windows"]
    lin_hosts = [h for h in falcon if h["platform_name"] == "Linux"]
    for cve, score, kev, product, desc, fix, platform in CVES:
        pool = win_hosts if platform == "Windows" else lin_hosts
        share = {"CVE-2023-4863": 0.10, "CVE-2023-5217": 0.07, "CVE-2024-21412": 0.06, "CVE-2024-38112": 0.08,
                 "CVE-2024-38063": 0.05, "CVE-2024-43491": 0.03, "CVE-2023-38831": 0.05, "CVE-2024-0727": 0.2,
                 "CVE-2024-4577": 0.02}.get(cve, 0.5)
        hosts = rng.sample(pool, max(1, int(len(pool) * share)))
        for h in hosts:
            first = now - timedelta(days=rng.choice([2, 5, 9, 12, 16, 21, 28, 35, 47, 63]), hours=rng.randint(0, 20))
            vulns.append({
                "id": f"{h['device_id']}_{cve}", "aid": h["device_id"], "status": "open",
                "created_timestamp": iso(first),
                "cve": {"id": cve, "base_score": score, "severity": None, "exprt_rating": rng.choice(["HIGH", "MEDIUM", "CRITICAL"]),
                        "description": desc, "cisa_info": {"is_cisa_kev": kev}},
                "host_info": {"hostname": h["hostname"], "platform_name": h["platform_name"]},
                "apps": [{"product_name_version": product}],
                "remediation": {"entities": [{"title": fix}]},
            })
    return intune, falcon, vulns


def collect_demo(ctx: Context) -> dict:
    intune_raw, falcon_raw, vulns_raw = build_raw()
    devices = merge_devices([normalise_intune(d) for d in intune_raw], [normalise_falcon_host(h) for h in falcon_raw])
    vulns = [v for v in (normalise_spotlight(x) for x in vulns_raw) if v]
    sources = {"intune": True, "falcon": True, "spotlight": True}
    return finalise(ctx, devices, vulns, [], set(), sources)


DEMO_IMPORT = [
    ("fw-edge-01", "CVE-2024-3400", 10.0, "critical", "PAN-OS GlobalProtect command injection", "Palo Alto PAN-OS 10.2",
     "Upgrade PAN-OS to a fixed hotfix release", 6),
    ("nas-backup-01", "CVE-2023-48795", 5.9, "medium", "SSH prefix truncation (Terrapin)", "NAS firmware SSH",
     "Apply the NAS firmware update", 40),
    ("ups-mgmt-01", "CVE-2023-44487", 7.5, "high", "HTTP/2 rapid reset denial of service", "UPS management card",
     "Apply vendor firmware or restrict the management interface", 25),
]


def seed_demo(ctx: Context) -> None:
    now = utcnow()
    if not ctx.db.scalar("SELECT COUNT(*) FROM imported_vulns", (), 0):
        with ctx.db.conn() as con:
            for host, cve, cvss, sev, title, product, fix, days in DEMO_IMPORT:
                con.execute(
                    """INSERT INTO imported_vulns (source, hostname, cve, title, cvss, severity, first_seen, product,
                    remediation, imported_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    ("Tenable Nessus (demo)", host, cve, title, cvss, sev, iso(now - timedelta(days=days)), product,
                     fix, iso(now)),
                )
    # Remediation history so trend and MTTR charts have something to show.
    if ctx.db.scalar("SELECT COUNT(*) FROM findings WHERE rule_id='VUL-001'", (), 0):
        return
    rng = random.Random(3)
    with ctx.db.conn() as con:
        for n in range(140):
            cve, score, *_ = rng.choice(CVES)
            first = now - timedelta(days=rng.randint(20, 90))
            fixed = first + timedelta(days=rng.choice([3, 5, 7, 9, 12, 15, 21, 30]))
            if fixed > now:
                continue
            sev = "critical" if score >= 9 else "high" if score >= 7 else "medium"
            fp = hashlib.sha256(f"history|{n}|{cve}".encode()).hexdigest()[:32]
            cur = con.execute(
                """INSERT INTO findings (fingerprint, rule_id, severity, title, entity_type, entity_id, entity_name,
                details_json, recommendation, status, owner, due_date, first_seen, last_seen, resolved_at)
                VALUES (?, 'VUL-001', ?, ?, 'device', ?, ?, ?, 'Patched', 'resolved', ?, ?, ?, ?, ?)""",
                (fp, sev, f"{cve} (historic)", f"hist-{n}", f"NWC-LT-{rng.randint(1, 110):04d}",
                 f'{{"cve": "{cve}", "cvss": {score}}}', rng.choice(["Desktop support", "Infrastructure team"]),
                 (first + timedelta(days=14)).date().isoformat(), iso(first), iso(fixed), iso(fixed)),
            )
            con.execute(
                "INSERT INTO finding_events (finding_id, ts, actor, event, detail) VALUES (?, ?, 'system', 'auto_resolved', 'Demo history')",
                (cur.lastrowid, iso(fixed)),
            )
