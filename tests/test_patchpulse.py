import io
from datetime import timedelta

import httpx

from patchpulse.catalog import host_key, severity_from_cvss, windows_build
from patchpulse.collector import collect_live
from patchpulse.core.db import iso, utcnow
from patchpulse.core.graph import GraphClient
from patchpulse.demo import collect_demo
from patchpulse.falcon import FalconClient
from patchpulse.rules import analyse, os_status, owner_for
from patchpulse.views import parse_scanner_csv

from .conftest import csrf


def test_demo_triggers_every_rule(ctx):
    findings = analyse(collect_demo(ctx), ctx.settings.all(), ctx)
    rules = {f.rule_id for f in findings}
    assert {f"EPC-{n:03d}" for n in range(1, 10)} | {"VUL-001"} <= rules, rules


def test_vulnerability_sla_and_kev(ctx):
    settings = ctx.settings.all()
    findings = analyse(collect_demo(ctx), settings, ctx)
    vulns = [f for f in findings if f.rule_id == "VUL-001"]
    kev = [f for f in vulns if f.details["kev"]]
    assert kev and all(f.severity == "critical" for f in kev)
    for f in vulns[:20]:
        assert f.due_date and f.first_seen


def test_helpers():
    assert host_key("NWC-LT-0001.corp.example") == "nwc-lt-0001"
    assert windows_build("10.0.22631.4317") == "22631"
    assert severity_from_cvss(9.8) == "critical" and severity_from_cvss(7.0) == "high"
    assert severity_from_cvss(4.0) == "medium" and severity_from_cvss(None) == "medium"


def test_os_lifecycle():
    win10 = {"platform": "Windows", "build": "19045", "server": False}
    eos, label, _ = os_status(win10, {}, "pro")
    assert eos == "2025-10-14" and "Windows 10" in label
    win11 = {"platform": "Windows", "build": "22631", "server": False}
    assert os_status(win11, {}, "enterprise")[0] == "2026-11-10"
    assert os_status(win11, {}, "pro")[0] == "2025-11-11"
    srv = {"platform": "Windows", "server": True, "falcon": {"os": "Windows Server 2016"}}
    assert os_status(srv, {}, "pro")[0] == "2027-01-12"


def test_owner_rules():
    rules = "server = Infra\nsrv-sql* = DBA\nplatform:macOS = Mac team\n* = Desktop"
    assert owner_for({"name": "srv-sql01", "server": True}, rules) == "Infra"
    assert owner_for({"name": "srv-sql01", "server": False}, rules) == "DBA"
    assert owner_for({"name": "mb1", "platform": "macOS"}, rules) == "Mac team"
    assert owner_for({"name": "x"}, rules) == "Desktop"
    assert owner_for({"name": "x"}, "") is None


def test_scanner_csv_parsing():
    text = ("Host,CVE,CVSS v3 Base Score,Risk,Name,Solution\n"
            "web01.corp,\"CVE-2024-0001, CVE-2024-0002\",9.1,Critical,Bad bug,Patch it\n"
            "web02,,5,Medium,No CVE,\n"
            "web03,CVE-2024-0003,abc,High,x,\n")
    rows, problems = parse_scanner_csv(text)
    assert [r["cve"] for r in rows] == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    assert rows[0]["severity"] == "critical" and rows[0]["cvss"] == 9.1
    assert rows[2]["cvss"] is None and rows[2]["severity"] == "high"
    assert parse_scanner_csv("a,b\n1,2\n")[0] == []


def test_csv_import_flows_into_findings(admin, ctx):
    token = csrf(admin, "/import")
    body = b"hostname,cve,cvss,first_seen\nnew-host-99,CVE-2024-9999,9.8,2020-01-01\n"
    r = admin.post("/import", data={"csrf_token": token, "source": "Test scanner"},
                   files={"file": ("s.csv", io.BytesIO(body), "text/csv")}, follow_redirects=False)
    assert r.status_code == 303
    ctx.scanner.run("test", "test")
    rows, _ = ctx.findings.search(rule_id="VUL-001", entity_id="new-host-99")
    assert rows and rows[0]["overdue"] and rows[0]["severity"] == "critical"
    admin.post("/import/delete", data={"csrf_token": token, "source": "Test scanner"})
    ctx.scanner.run("test", "test")
    assert ctx.findings.search(status="resolved", entity_id="new-host-99")[1] == 1


def test_live_collector_joins_intune_and_falcon(ctx):
    now = utcnow()

    def graph_handler(req: httpx.Request):
        if req.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        return httpx.Response(200, json={"value": [
            {"id": "d1", "deviceName": "LT-1", "operatingSystem": "Windows", "osVersion": "10.0.19045.1",
             "complianceState": "noncompliant", "lastSyncDateTime": iso(now), "isEncrypted": False},
            {"id": "d2", "deviceName": "LT-2", "operatingSystem": "Windows", "osVersion": "10.0.26200.1",
             "complianceState": "compliant", "lastSyncDateTime": iso(now), "isEncrypted": True},
        ]})

    def falcon_handler(req: httpx.Request):
        p = req.url.path
        if p == "/oauth2/token":
            return httpx.Response(201, json={"access_token": "f", "expires_in": 1799})
        if p == "/oauth2/revoke":
            return httpx.Response(200, json={})
        if p == "/devices/queries/devices-scroll/v1":
            return httpx.Response(200, json={"resources": ["a1", "a2"], "meta": {"pagination": {"offset": ""}}})
        if p == "/devices/entities/devices/v2":
            return httpx.Response(200, json={"resources": [
                {"device_id": "a1", "hostname": "lt-1.corp.example", "platform_name": "Windows",
                 "os_product_name": "Windows 10", "last_seen": iso(now - timedelta(days=20)), "product_type_desc": "Workstation"},
                {"device_id": "a2", "hostname": "KIOSK-1", "platform_name": "Windows", "os_product_name": "Windows 11",
                 "last_seen": iso(now), "product_type_desc": "Workstation"}]})
        if p == "/spotlight/combined/vulnerabilities/v1":
            return httpx.Response(200, json={"resources": [
                {"aid": "a1", "created_timestamp": iso(now - timedelta(days=30)),
                 "cve": {"id": "cve-2024-1111", "base_score": 8.1, "severity": "HIGH"},
                 "host_info": {"hostname": "LT-1"}, "remediation": {"entities": [{"title": "Update"}]}}],
                "meta": {"pagination": {"after": ""}}})
        return httpx.Response(404, json={"errors": [{"message": p}]})

    graph = GraphClient("t", "c", "s", transport=httpx.MockTransport(graph_handler), sleep=lambda s: None)
    falcon = FalconClient("id", "secret", transport=httpx.MockTransport(falcon_handler), sleep=lambda s: None)
    ctx.settings.set_many({"kev_enrich": False}, "test")
    ctx.db.execute("DELETE FROM imported_vulns")
    data = collect_live(ctx, graph=graph, falcon=falcon)
    keys = {d["key"]: d for d in data["devices"]}
    assert set(keys) == {"lt-1", "lt-2", "kiosk-1"}
    assert keys["lt-1"]["falcon"] and keys["lt-1"]["intune"]
    findings = analyse(data, ctx.settings.all(), ctx)
    by_rule = {(f.rule_id, f.entity_id) for f in findings}
    assert ("EPC-001", "lt-1") in by_rule and ("EPC-003", "lt-1") in by_rule
    assert ("EPC-004", "lt-1") in by_rule and ("EPC-008", "lt-1") in by_rule
    assert ("EPC-006", "lt-2") in by_rule and ("EPC-007", "kiosk-1") in by_rule
    vuln = next(f for f in findings if f.rule_id == "VUL-001")
    assert vuln.details["cve"] == "CVE-2024-1111" and vuln.severity == "high"
