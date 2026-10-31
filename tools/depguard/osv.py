"""OSV.dev vulnerability lookups for PyPI packages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from depguard.http import JsonClient
from depguard.names import normalize

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"


@dataclass(frozen=True, slots=True)
class Vulnerability:
    id: str
    summary: str
    aliases: tuple[str, ...]
    fixed_versions: tuple[str, ...]
    severity: str | None

    @property
    def display_id(self) -> str:
        cves = [a for a in self.aliases if a.startswith("CVE-")]
        return f"{self.id} ({cves[0]})" if cves else self.id


def _fixed_versions(vuln: dict[str, Any], package: str) -> tuple[str, ...]:
    fixed: list[str] = []
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != "PyPI" or normalize(pkg.get("name", "")) != package:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":  # skip GIT ranges (commit hashes)
                continue
            fixed.extend(e["fixed"] for e in rng.get("events", []) if "fixed" in e)
    return tuple(dict.fromkeys(fixed))


def _severity(vuln: dict[str, Any]) -> str | None:
    db = vuln.get("database_specific") or {}
    if isinstance(db, dict) and db.get("severity"):
        return str(db["severity"]).upper()
    for entry in vuln.get("severity", []):
        if entry.get("type", "").startswith("CVSS"):
            return f"CVSS {entry.get('score')}"
    return None


def vulnerability_from_json(vuln: dict[str, Any], package: str) -> Vulnerability:
    return Vulnerability(
        id=str(vuln.get("id", "")),
        summary=str(vuln.get("summary") or vuln.get("details", ""))[:160],
        aliases=tuple(vuln.get("aliases") or ()),
        fixed_versions=_fixed_versions(vuln, package),
        severity=_severity(vuln),
    )


class OSVClient:
    def __init__(self, http: JsonClient | None = None) -> None:
        self.http = http or JsonClient(cache_ttl_seconds=3600)

    def query(self, name: str, version: str) -> tuple[Vulnerability, ...]:
        package = normalize(name)
        payload = {"version": version, "package": {"name": package, "ecosystem": "PyPI"}}
        response = self.http.request(OSV_QUERY, method="POST", payload=payload)
        body = response.body or {}
        return tuple(vulnerability_from_json(v, package) for v in body.get("vulns", []))

    def query_batch(self, pins: list[tuple[str, str]]) -> dict[tuple[str, str], tuple[str, ...]]:
        """Return ``{(name, version): (vuln_id, ...)}`` for pins that have advisories."""
        results: dict[tuple[str, str], tuple[str, ...]] = {}
        chunk_size = 500  # OSV batch limit is 1000 queries
        for start in range(0, len(pins), chunk_size):
            chunk = pins[start : start + chunk_size]
            payload = {
                "queries": [
                    {"version": v, "package": {"name": normalize(n), "ecosystem": "PyPI"}}
                    for n, v in chunk
                ]
            }
            response = self.http.request(OSV_QUERY_BATCH, method="POST", payload=payload)
            for pin, result in zip(chunk, (response.body or {}).get("results", []), strict=False):
                ids = tuple(v["id"] for v in result.get("vulns", []))
                if ids:
                    results[(normalize(pin[0]), pin[1])] = ids
        return results
