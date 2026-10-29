"""Session login, roles, CSRF protection and API-token auth."""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import Request
from starlette.datastructures import FormData

from .config import Config

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"


class LoginRequired(Exception):
    def __init__(self, next_path: str = "/"):
        self.next_path = next_path


class Forbidden(Exception):
    def __init__(self, message: str = "You do not have permission to do that."):
        self.message = message


class ApiUnauthorized(Exception):
    pass


def _eq(a: str, b: str) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())


def check_credentials(config: Config, username: str, password: str) -> str | None:
    username = (username or "").strip()
    if _eq(username, config.admin_username) and _eq(password, config.admin_password):
        return ROLE_ADMIN
    if config.viewer_password and _eq(username, config.viewer_username) and _eq(
        password, config.viewer_password
    ):
        return ROLE_VIEWER
    return None


class LoginThrottle:
    """Allow `limit` failed attempts per client per `window` seconds."""

    def __init__(self, limit: int = 5, window: int = 300):
        self.limit = limit
        self.window = window
        self._fails: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str) -> deque:
        q = self._fails[key]
        cutoff = time.monotonic() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key)) >= self.limit

    def fail(self, key: str) -> None:
        with self._lock:
            self._prune(key).append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def current_user(request: Request) -> dict | None:
    user = request.session.get("user")
    if not user:
        return None
    if user.get("exp", 0) < time.time():
        request.session.clear()
        return None
    return user


def login(request: Request, username: str, role: str, hours: float = 8) -> None:
    request.session.clear()
    request.session["user"] = {"name": username, "role": role, "exp": time.time() + hours * 3600}
    request.session["csrf"] = secrets.token_urlsafe(32)


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def safe_next(path: str | None) -> str:
    if not path or not path.startswith("/") or path.startswith("//") or "\\" in path:
        return "/"
    return path


# ----------------------------------------------------------------- dependencies
async def require_user(request: Request) -> dict:
    user = current_user(request)
    if not user:
        nxt = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        raise LoginRequired(nxt)
    return user


async def require_admin_form(request: Request) -> FormData:
    """For state-changing POSTs: logged-in admin + valid CSRF token. Returns the parsed form."""
    user = await require_user(request)
    form = await request.form()
    sent = str(form.get("csrf_token", ""))
    if not _eq(sent, request.session.get("csrf", "")):
        raise Forbidden("Your session expired or the form was tampered with. Reload the page and try again.")
    if user["role"] != ROLE_ADMIN:
        raise Forbidden("Read-only accounts cannot make changes.")
    return form


async def require_api(request: Request) -> dict:
    config: Config = request.app.state.ctx.config
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer ") and config.api_token:
        if _eq(header[7:].strip(), config.api_token):
            return {"name": "api-token", "role": ROLE_VIEWER}
    user = current_user(request)
    if user:
        return user
    raise ApiUnauthorized()
