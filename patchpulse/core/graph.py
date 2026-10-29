"""Read-only Microsoft Graph client (OAuth2 client-credentials flow).

The client deliberately exposes GET requests only: the app never writes to your tenant.
It handles paging (@odata.nextLink), throttling (429/503/504 with Retry-After) and token caching.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

RETRY_STATUSES = {429, 500, 502, 503, 504}


class GraphError(RuntimeError):
    def __init__(self, status: int, code: str, message: str, url: str = ""):
        self.status = status
        self.code = code
        self.url = url
        super().__init__(f"Graph {status} {code}: {message}")


class GraphClient:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        base: str = "https://graph.microsoft.com/v1.0",
        beta_base: str = "https://graph.microsoft.com/beta",
        authority: str = "https://login.microsoftonline.com",
        transport: httpx.BaseTransport | None = None,
        timeout: float = 60.0,
        max_retries: int = 5,
        sleep=time.sleep,
    ):
        if not (tenant_id and client_id and client_secret):
            raise ValueError("Graph credentials are incomplete.")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self._secret = client_secret
        self.base = base.rstrip("/")
        self.beta_base = beta_base.rstrip("/")
        self.authority = authority.rstrip("/")
        self.max_retries = max_retries
        self._sleep = sleep
        self._token: str | None = None
        self._token_exp = 0.0
        self.http = httpx.Client(
            transport=transport,
            timeout=timeout,
            headers={"User-Agent": "nhi-saas-toolkit/1.0", "Accept": "application/json"},
        )
        self.calls = 0

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> GraphClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ auth
    def token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        url = f"{self.authority}/{self.tenant_id}/oauth2/v2.0/token"
        resp = self.http.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self._secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        if resp.status_code != 200:
            try:
                body = resp.json()
                msg = body.get("error_description", "").split("\r\n")[0] or body.get("error", "")
            except ValueError:
                msg = resp.text[:200]
            raise GraphError(resp.status_code, "token_error", msg or "token request failed", url)
        body = resp.json()
        self._token = body["access_token"]
        self._token_exp = time.time() + int(body.get("expires_in", 3600))
        return self._token

    # ---------------------------------------------------------------- reads
    def _url(self, path: str, beta: bool) -> str:
        if path.startswith("https://"):
            return path
        base = self.beta_base if beta else self.base
        return f"{base}/{path.lstrip('/')}"

    def get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        beta: bool = False,
        headers: dict[str, str] | None = None,
    ) -> dict:
        url = self._url(path, beta)
        attempt = 0
        while True:
            attempt += 1
            hdrs = {"Authorization": f"Bearer {self.token()}", **(headers or {})}
            self.calls += 1
            try:
                resp = self.http.get(url, params=params, headers=hdrs)
            except httpx.TransportError as exc:
                if attempt > self.max_retries:
                    raise GraphError(0, "network_error", str(exc), url) from exc
                self._sleep(min(2**attempt, 30))
                continue
            if resp.status_code == 401 and attempt == 1:
                self._token = None
                continue
            if resp.status_code in RETRY_STATUSES and attempt <= self.max_retries:
                retry_after = resp.headers.get("Retry-After")
                try:
                    wait = float(retry_after) if retry_after else min(2**attempt, 30)
                except ValueError:
                    wait = min(2**attempt, 30)
                log.info("Graph throttled (%s), retrying in %.0fs", resp.status_code, wait)
                self._sleep(min(wait, 120))
                continue
            if resp.status_code >= 400:
                try:
                    err = resp.json().get("error", {})
                    code, msg = err.get("code", "error"), err.get("message", "")
                except ValueError:
                    code, msg = "error", resp.text[:200]
                raise GraphError(resp.status_code, code, msg, url)
            return resp.json() if resp.content else {}

    def get_all(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        beta: bool = False,
        headers: dict[str, str] | None = None,
        max_pages: int = 1000,
    ) -> list[dict]:
        items: list[dict] = []
        body = self.get(path, params=params, beta=beta, headers=headers)
        items.extend(body.get("value", []))
        pages = 1
        while body.get("@odata.nextLink") and pages < max_pages:
            body = self.get(body["@odata.nextLink"], headers=headers)
            items.extend(body.get("value", []))
            pages += 1
        return items


def graph_client_from_config(config, transport: httpx.BaseTransport | None = None) -> GraphClient:
    return GraphClient(
        config.tenant_id,
        config.client_id,
        config.client_secret,
        base=config.graph_base,
        beta_base=config.graph_beta_base,
        authority=config.authority,
        transport=transport,
    )
