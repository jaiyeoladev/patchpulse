"""Read-only CrowdStrike Falcon API client (hosts + Spotlight vulnerabilities).

API client scopes required: Hosts: Read, Vulnerabilities (Spotlight): Read.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
}


class FalconError(RuntimeError):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(f"Falcon {status}: {message}")


class FalconClient:
    def __init__(self, client_id: str, client_secret: str, base_url: str = CLOUDS["us-1"],
                 transport: httpx.BaseTransport | None = None, timeout: float = 60.0, sleep=time.sleep):
        if not (client_id and client_secret):
            raise ValueError("Falcon credentials are incomplete.")
        base_url = CLOUDS.get(base_url, base_url)
        self.base = base_url.rstrip("/")
        self._id, self._secret = client_id, client_secret
        self._token: str | None = None
        self._exp = 0.0
        self._sleep = sleep
        self.http = httpx.Client(transport=transport, timeout=timeout,
                                 headers={"User-Agent": "patchpulse/1.0", "Accept": "application/json"})
        self.calls = 0

    def close(self) -> None:
        if self._token:
            try:
                self.http.post(f"{self.base}/oauth2/revoke", data={"token": self._token},
                               auth=(self._id, self._secret))
            except httpx.HTTPError:
                pass
        self.http.close()

    def token(self) -> str:
        if self._token and time.time() < self._exp - 60:
            return self._token
        r = self.http.post(f"{self.base}/oauth2/token", data={"client_id": self._id, "client_secret": self._secret})
        if r.status_code not in (200, 201):
            raise FalconError(r.status_code, "authentication failed - check the API client ID, secret and cloud")
        body = r.json()
        self._token = body["access_token"]
        self._exp = time.time() + int(body.get("expires_in", 1799))
        return self._token

    def _request(self, method: str, path: str, **kw: Any) -> dict:
        for attempt in range(1, 6):
            self.calls += 1
            r = self.http.request(method, f"{self.base}{path}", headers={"Authorization": f"Bearer {self.token()}"}, **kw)
            if r.status_code == 429 or r.status_code >= 500:
                reset = r.headers.get("X-RateLimit-RetryAfter")
                wait = max(1.0, float(reset) - time.time()) if reset and reset.isdigit() else 2 ** attempt
                self._sleep(min(wait, 60))
                continue
            if r.status_code == 401 and attempt == 1:
                self._token = None
                continue
            if r.status_code >= 400:
                try:
                    errs = r.json().get("errors") or []
                    msg = "; ".join(e.get("message", "") for e in errs) or r.text[:200]
                except ValueError:
                    msg = r.text[:200]
                if r.status_code == 403:
                    msg += " (the API client needs Hosts: Read and Vulnerabilities: Read scopes)"
                raise FalconError(r.status_code, msg)
            return r.json()
        raise FalconError(429, "rate limited after retries")

    def hosts(self, limit: int = 5000, max_hosts: int = 100000) -> list[dict]:
        ids: list[str] = []
        offset = ""
        while len(ids) < max_hosts:
            params = {"limit": limit}
            if offset:
                params["offset"] = offset
            body = self._request("GET", "/devices/queries/devices-scroll/v1", params=params)
            batch = body.get("resources") or []
            ids += batch
            offset = ((body.get("meta") or {}).get("pagination") or {}).get("offset") or ""
            if not batch or not offset:
                break
        details: list[dict] = []
        for i in range(0, len(ids), 5000):
            body = self._request("POST", "/devices/entities/devices/v2", json={"ids": ids[i:i + 5000]})
            details += body.get("resources") or []
        return details

    def vulnerabilities(self, limit: int = 5000, max_items: int = 200000) -> list[dict]:
        out: list[dict] = []
        after = ""
        while len(out) < max_items:
            params: list[tuple[str, str]] = [
                ("filter", "status:['open','reopen']"), ("limit", str(limit)),
                ("facet", "cve"), ("facet", "host_info"), ("facet", "remediation"),
            ]
            if after:
                params.append(("after", after))
            body = self._request("GET", "/spotlight/combined/vulnerabilities/v1", params=params)
            batch = body.get("resources") or []
            out += batch
            after = ((body.get("meta") or {}).get("pagination") or {}).get("after") or ""
            if not batch or not after:
                break
        return out
