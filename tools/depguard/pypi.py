"""PyPI JSON API client → immutable :class:`PackageInfo`."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from depguard.http import JsonClient
from depguard.names import normalize
from depguard.versions import try_parse_version

if TYPE_CHECKING:
    from depguard.versions import Version

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
PYPI_PROVENANCE = "https://pypi.org/integrity/{name}/{version}/{filename}/provenance"


@dataclass(frozen=True, slots=True)
class Release:
    version: str
    uploaded_at: datetime | None
    yanked: bool
    has_wheel: bool
    filenames: tuple[str, ...]

    @property
    def parsed(self) -> Version | None:
        return try_parse_version(self.version)


@dataclass(frozen=True, slots=True)
class PackageInfo:
    name: str
    summary: str
    license: str | None
    classifiers: tuple[str, ...]
    requires_python: str | None
    project_urls: dict[str, str]
    requires_dist: tuple[str, ...]
    releases: tuple[Release, ...]
    latest_version: str

    @property
    def normalized_name(self) -> str:
        return normalize(self.name)

    @property
    def first_upload(self) -> datetime | None:
        dates = [r.uploaded_at for r in self.releases if r.uploaded_at]
        return min(dates) if dates else None

    @property
    def last_upload(self) -> datetime | None:
        dates = [r.uploaded_at for r in self.releases if r.uploaded_at]
        return max(dates) if dates else None

    def release(self, version: str) -> Release | None:
        wanted = try_parse_version(version)
        for rel in self.releases:
            if rel.version == version or (wanted is not None and rel.parsed == wanted):
                return rel
        return None

    def stable_releases(self) -> list[Release]:
        parsed = [(r, r.parsed) for r in self.releases if not r.yanked]
        stable = [(r, v) for r, v in parsed if v is not None and not v.is_prerelease]
        return [r for r, _ in sorted(stable, key=lambda pair: pair[1])]

    def latest_stable_before(self, cutoff: datetime) -> Release | None:
        """Newest stable release uploaded at or before ``cutoff`` (cooldown-aware)."""
        candidates = [
            r for r in self.stable_releases() if r.uploaded_at and r.uploaded_at <= cutoff
        ]
        return candidates[-1] if candidates else None


def _parse_time(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _release_from_files(version: str, files: list[dict[str, Any]]) -> Release:
    times = [_parse_time(f.get("upload_time_iso_8601")) for f in files]
    valid = [t for t in times if t is not None]
    return Release(
        version=version,
        uploaded_at=min(valid) if valid else None,
        yanked=bool(files) and all(f.get("yanked", False) for f in files),
        has_wheel=any(f.get("packagetype") == "bdist_wheel" for f in files),
        filenames=tuple(str(f.get("filename", "")) for f in files),
    )


def package_info_from_json(data: dict[str, Any]) -> PackageInfo:
    info = data.get("info", {})
    releases = tuple(
        _release_from_files(version, files)
        for version, files in data.get("releases", {}).items()
        if files  # versions with no files were never really published
    )
    license_text = info.get("license_expression") or info.get("license") or None
    if license_text and len(license_text) > 200:  # full license body pasted into the field
        license_text = None
    return PackageInfo(
        name=str(info.get("name", "")),
        summary=str(info.get("summary") or ""),
        license=license_text,
        classifiers=tuple(info.get("classifiers") or ()),
        requires_python=info.get("requires_python") or None,
        project_urls=dict(info.get("project_urls") or {}),
        requires_dist=tuple(info.get("requires_dist") or ()),
        releases=releases,
        latest_version=str(info.get("version", "")),
    )


class PyPIClient:
    def __init__(self, http: JsonClient | None = None) -> None:
        self.http = http or JsonClient()

    def fetch(self, name: str) -> PackageInfo | None:
        response = self.http.request(PYPI_JSON.format(name=normalize(name)))
        if response.status == 404 or not isinstance(response.body, dict):
            return None
        return package_info_from_json(response.body)

    def has_provenance(self, name: str, version: str, filename: str) -> bool | None:
        """PEP 740 attestation lookup. ``None`` means the lookup itself failed."""
        url = PYPI_PROVENANCE.format(name=normalize(name), version=version, filename=filename)
        try:
            response = self.http.request(url, accept="application/vnd.pypi.integrity.v1+json")
        except Exception:
            return None
        return response.status == 200
