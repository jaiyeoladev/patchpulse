import importlib
import re

import pytest
from fastapi.testclient import TestClient

from patchpulse.core.config import Config

APP_MODULE = importlib.import_module("patchpulse.app")


def make_config(tmp_path, **overrides) -> Config:
    values = dict(
        slug=APP_MODULE.SPEC.slug,
        demo_mode=True,
        database_path=str(tmp_path / "test.db"),
        secret_key="test-secret-key-0123456789",
        admin_password="admin-password-123",
        viewer_password="viewer-password-123",
        api_token="test-api-token",
    )
    values.update(overrides)
    cfg = Config(**values)
    cfg.validate()
    return cfg


def login(client: TestClient, username: str = "admin", password: str = "admin-password-123"):
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token, "next": "/"},
                       follow_redirects=False)


def csrf(client: TestClient, path: str = "/settings") -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).text).group(1)


@pytest.fixture()
def config(tmp_path):
    return make_config(tmp_path)


@pytest.fixture()
def app(config):
    return APP_MODULE.build(config)


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin(client):
    assert login(client).status_code == 303
    return client


@pytest.fixture()
def ctx(app, client):
    return app.state.ctx
