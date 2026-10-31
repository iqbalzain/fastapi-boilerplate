"""Tiny HTTP JSON client with an on-disk cache. urllib only."""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from depguard import __version__

USER_AGENT = f"depguard/{__version__} (+https://github.com/your-org/fastapi-boilerplate)"
DEFAULT_CACHE_DIR = Path(".depguard-cache")
DEFAULT_TIMEOUT = 15.0


class NetworkError(RuntimeError):
    """The upstream service could not be reached or answered unexpectedly."""


@dataclass(frozen=True, slots=True)
class JsonResponse:
    status: int
    body: Any


class JsonClient:
    def __init__(
        self,
        *,
        cache_dir: Path | None = DEFAULT_CACHE_DIR,
        cache_ttl_seconds: int = 6 * 3600,
        timeout: float = DEFAULT_TIMEOUT,
        offline: bool = False,
    ) -> None:
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl_seconds
        self.timeout = timeout
        self.offline = offline

    # -- cache ---------------------------------------------------------------
    def _cache_path(self, key: str) -> Path | None:
        if self.cache_dir is None:
            return None
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, key: str) -> JsonResponse | None:
        path = self._cache_path(key)
        if path is None or not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if time.time() - float(entry.get("fetched_at", 0)) > self.cache_ttl and not self.offline:
            return None
        return JsonResponse(status=int(entry["status"]), body=entry["body"])

    def _write_cache(self, key: str, response: JsonResponse) -> None:
        path = self._cache_path(key)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"fetched_at": time.time(), "status": response.status, "body": response.body}
        path.write_text(json.dumps(payload), encoding="utf-8")

    # -- requests ------------------------------------------------------------
    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        payload: Any | None = None,
        accept: str | None = None,
    ) -> JsonResponse:
        key = f"{method} {url} {json.dumps(payload, sort_keys=True) if payload else ''}"
        cached = self._read_cache(key)
        if cached is not None:
            return cached
        if self.offline:
            raise NetworkError(f"offline mode and no cached response for {url}")
        response = self._fetch(url, method=method, payload=payload, accept=accept)
        if response.status in (200, 404):
            self._write_cache(key, response)
        return response

    def _fetch(
        self, url: str, *, method: str, payload: Any | None, accept: str | None
    ) -> JsonResponse:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"User-Agent": USER_AGENT, "Accept": accept or "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310 - https only
        if not url.startswith("https://"):
            raise NetworkError(f"refusing non-HTTPS URL {url}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310  # nosec B310 - https enforced above
                raw = resp.read()
                body = json.loads(raw) if raw else None
                return JsonResponse(status=resp.status, body=body)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return JsonResponse(status=404, body=None)
            raise NetworkError(f"{url} returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise NetworkError(f"{url}: {exc}") from exc
