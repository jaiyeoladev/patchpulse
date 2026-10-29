"""Tests for the shared core: findings lifecycle, settings, Graph client, auth and security."""

from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from patchpulse.core.db import Database, iso, utcnow
from patchpulse.core.findings import Finding, FindingError, FindingStore
from patchpulse.core.graph import GraphClient, GraphError
from patchpulse.core.settings import SettingDef, SettingsError, SettingsStore
from patchpulse.core.web import _csv_safe

from .conftest import APP_MODULE, csrf, login, make_config


@pytest.fixture()
def store(tmp_path):
    db = Database(str(tmp_path / "f.db"))
    db.init()
    return FindingStore(db)


def f(entity="e1", sev="high", key=""):
    return Finding("T-1", sev, "Test finding", "thing", entity, entity.upper(), {"a": 1}, "Fix it", key=key)


# ------------------------------------------------------------------- findings
def test_sync_creates_updates_and_auto_resolves(store):
    s1 = store.sync(1, [f("a"), f("b")])
    assert s1["new"] == 2
    s2 = store.sync(2, [f("a", sev="critical")])
    assert s2 == {"new": 0, "reopened": 0, "updated": 1, "resolved": 1, "exceptions_expired": 0}
    rows, total = store.search(status="all")
    assert total == 2
    by_entity = {r["entity_id"]: r for r in rows}
    assert by_entity["a"]["severity"] == "critical"
    assert by_entity["b"]["status"] == "resolved"


def test_resolved_finding_reopens_when_detected_again(store):
    store.sync(1, [f("a")])
    store.sync(2, [])
    store.sync(3, [f("a")])
    row = store.search(status="all")[0][0]
    assert row["status"] == "open"
    assert row["reopen_count"] == 1
    assert row["resolved_at"] is None


def test_duplicate_fingerprints_keep_highest_severity(store):
    store.sync(1, [f("a", "low"), f("a", "critical")])
    rows, total = store.search(status="all")
    assert total == 1 and rows[0]["severity"] == "critical"


def test_risk_acceptance_validation_and_expiry(store):
    store.sync(1, [f("a")])
    fid = store.search()[0][0]["id"]
    with pytest.raises(FindingError):
        store.apply(fid, "accept", "tester", justification="short", accepted_until="2999-01-01")
    with pytest.raises(FindingError):
        store.apply(fid, "accept", "tester", justification="valid business reason", accepted_until="2999-01-01")
    until = (utcnow().date() + timedelta(days=30)).isoformat()
    assert store.apply(fid, "accept", "tester", justification="valid business reason", accepted_until=until)["status"] == "accepted"
    store.sync(2, [f("a")])
    assert store.get(fid)["status"] == "accepted"
    store.db.execute("UPDATE findings SET accepted_until = '2000-01-01' WHERE id = ?", (fid,))
    stats = store.sync(3, [f("a")])
    assert stats["exceptions_expired"] == 1
    assert store.get(fid)["status"] == "open"


def test_actions_record_history_and_owner(store):
    store.sync(1, [f("a")])
    fid = store.search()[0][0]["id"]
    store.apply(fid, "assign", "tester", owner="Infra team")
    store.apply(fid, "acknowledge", "tester")
    store.apply(fid, "comment", "tester", comment="Raised ticket INC123")
    got = store.get(fid)
    assert got["owner"] == "Infra team" and got["status"] == "acknowledged"
    assert [e["event"] for e in got["events"]][:3] == ["comment", "acknowledge", "assign"]
    with pytest.raises(FindingError):
        store.apply(fid, "explode", "tester")


def test_overdue_flag(store):
    old = Finding("T-1", "high", "x", "thing", "a", "A", due_date=(utcnow() - timedelta(days=3)).date().isoformat())
    store.sync(1, [old])
    row = store.search(overdue=True)[0][0]
    assert row["overdue"] and row["days_overdue"] == 3


# ------------------------------------------------------------------- settings
def test_settings_coercion_and_bounds(tmp_path):
    db = Database(str(tmp_path / "s.db"))
    db.init()
    s = SettingsStore(db, [SettingDef("n", "Number", "int", 5, min=1, max=10),
                           SettingDef("j", "Json", "json", {"a": 1}),
                           SettingDef("c", "Choice", "text", "x", choices=[("x", "X"), ("y", "Y")])])
    assert s.all() == {"n": 5, "j": {"a": 1}, "c": "x"}
    s.set_many({"n": "7", "j": '{"b": 2}', "c": "y"}, "tester")
    assert s.all() == {"n": 7, "j": {"b": 2}, "c": "y"}
    for bad in ({"n": "11"}, {"n": "abc"}, {"j": "{"}, {"c": "z"}):
        with pytest.raises(SettingsError):
            s.set_many(bad, "tester")


# ---------------------------------------------------------------------- graph
def test_graph_client_pages_and_retries():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        assert request.headers["Authorization"] == "Bearer tok"
        assert request.method == "GET"
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        if "page2" in str(request.url):
            return httpx.Response(200, json={"value": [{"id": 3}]})
        return httpx.Response(200, json={"value": [{"id": 1}, {"id": 2}],
                                         "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page2=1"})

    c = GraphClient("t", "c", "s", transport=httpx.MockTransport(handler), sleep=lambda s: None)
    assert [x["id"] for x in c.get_all("users")] == [1, 2, 3]


def test_graph_client_raises_with_code():
    def handler(request):
        if "token" in request.url.path:
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied", "message": "no"}})

    c = GraphClient("t", "c", "s", transport=httpx.MockTransport(handler), sleep=lambda s: None)
    with pytest.raises(GraphError) as exc:
        c.get("users")
    assert exc.value.status == 403 and exc.value.code == "Authorization_RequestDenied"


# ----------------------------------------------------------------- web & auth
def test_login_required_and_security_headers(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    r = client.get("/login")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/healthz").text == "ok"


def test_bad_password_and_open_redirect(client):
    assert login(client, password="wrong").status_code == 401
    page = client.get("/login?next=//evil.example")
    assert 'value="/"' in page.text


def test_pages_render_for_admin(admin):
    for path in ["/", "/findings", "/scans", "/settings", "/rules", "/audit", "/report", "/connection"]:
        r = admin.get(path)
        assert r.status_code == 200, path
    for item in APP_MODULE.SPEC.nav:
        assert admin.get(item.href).status_code == 200, item.href


def test_csrf_is_enforced(admin):
    r = admin.post("/scans/run", data={"csrf_token": "nope"})
    assert r.status_code == 403


def test_viewer_is_read_only(client):
    assert login(client, "auditor", "viewer-password-123").status_code == 303
    assert client.get("/findings").status_code == 200
    r = client.post("/settings", data={"csrf_token": csrf(client)})
    assert r.status_code == 403


def test_finding_workflow_via_ui(admin, ctx):
    fid = ctx.findings.search()[0][0]["id"]
    token = csrf(admin, f"/findings/{fid}")
    r = admin.post(f"/findings/{fid}/action", data={"csrf_token": token, "action": "assign", "owner": "Team A"},
                   follow_redirects=False)
    assert r.status_code == 303
    assert ctx.findings.get(fid)["owner"] == "Team A"
    r = admin.post("/findings/bulk", data={"csrf_token": token, "action": "acknowledge", "ids": [str(fid)]})
    assert ctx.findings.get(fid)["status"] == "acknowledged"


def test_settings_save(admin, ctx):
    key = next(d for d in APP_MODULE.SPEC.setting_defs if d.type == "int")
    value = int(key.min or 1) + 1 if key.max is None or (key.min or 1) + 1 <= key.max else int(key.min)
    form = {"csrf_token": csrf(admin)}
    for d in APP_MODULE.SPEC.setting_defs:
        if d.hidden or d.type == "bool":
            continue
        current = ctx.settings.all()[d.key]
        form[d.key] = __import__("json").dumps(current) if d.type == "json" else str(current)
    form[key.key] = str(value)
    assert admin.post("/settings", data=form).status_code == 200
    assert ctx.settings.get(key.key) == value


def test_api_requires_token(client):
    assert client.get("/api/summary").status_code == 401
    r = client.get("/api/summary", headers={"Authorization": "Bearer test-api-token"})
    assert r.status_code == 200 and r.json()["app"] == APP_MODULE.SPEC.slug
    assert client.get("/api/findings", headers={"Authorization": "Bearer test-api-token"}).json()["total"] > 0


def test_csv_export_neutralises_formulas(admin):
    assert _csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    r = admin.get("/findings.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")


def test_live_mode_requires_strong_password(tmp_path):
    with pytest.raises(RuntimeError):
        make_config(tmp_path, demo_mode=False, admin_password="short")


def test_live_mode_without_credentials_reports_missing(tmp_path):
    cfg = make_config(tmp_path, demo_mode=False, admin_password="a-very-long-password")
    app = APP_MODULE.build(cfg)
    with TestClient(app) as c:
        ctx = app.state.ctx
        if ctx.spec.live_requirements(ctx):
            scan_id = ctx.scanner.run("test", "test")
            row = ctx.db.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
            assert row["status"] == "failed" and "missing" in row["error"]
        assert c.get("/healthz").status_code == 200


def test_iso_roundtrip():
    from patchpulse.core.db import parse_dt

    assert parse_dt("2026-01-02T03:04:05.1234567Z").microsecond == 123456
    assert parse_dt("0001-01-01T00:00:00Z") is None
    assert iso(parse_dt("2026-01-02")) == "2026-01-02T00:00:00Z"
