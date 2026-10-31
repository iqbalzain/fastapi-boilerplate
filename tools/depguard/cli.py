"""Command-line entry point: ``python -m depguard <vet|add|audit|outdated>``."""

from __future__ import annotations

import argparse
import subprocess  # nosec B404 - fixed argv, never shell=True
import sys
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from depguard.checks import VetContext, VetResult, vet_package
from depguard.http import JsonClient, NetworkError
from depguard.lockfile import (
    LOCK_PATH,
    LockedPackage,
    diff_locks,
    direct_dependencies,
    lock_at_ref,
    read_lock,
)
from depguard.osv import OSVClient
from depguard.policy import PolicyError, load_policy
from depguard.pypi import PyPIClient
from depguard.report import (
    render_table,
    render_vet_json,
    render_vet_markdown,
    render_vet_text,
)
from depguard.versions import bump_kind, try_parse_version

if TYPE_CHECKING:
    from collections.abc import Sequence

EXIT_OK, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2


def build_context(args: argparse.Namespace) -> VetContext:
    policy = load_policy(Path(args.policy) if args.policy else None)
    cache_dir = None if args.no_cache else Path(".depguard-cache")
    http = JsonClient(cache_dir=cache_dir, offline=args.offline)
    return VetContext(
        policy=policy,
        pypi=PyPIClient(http),
        osv=OSVClient(
            JsonClient(cache_dir=cache_dir, cache_ttl_seconds=3600, offline=args.offline)
        ),
        check_provenance=not args.offline,
    )


def _render(results: Sequence[VetResult], fmt: str, *, verbose: bool) -> str:
    if fmt == "json":
        return render_vet_json(results)
    if fmt == "markdown":
        return render_vet_markdown(results)
    return render_vet_text(results, verbose=verbose)


def _exit_code(results: Sequence[VetResult]) -> int:
    return EXIT_BLOCKED if any(r.failed for r in results) else EXIT_OK


# --- vet ----------------------------------------------------------------------
def cmd_vet(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    results = [vet_package(spec, ctx) for spec in args.packages]
    print(_render(results, args.format, verbose=args.verbose))
    return _exit_code(results)


# --- add ----------------------------------------------------------------------
def cmd_add(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    results = [vet_package(spec, ctx) for spec in args.packages]
    print(render_vet_text(results, verbose=args.verbose))
    if _exit_code(results) != EXIT_OK:
        print(
            "\nRefusing to install. Fix the findings or add a reviewed exception to depguard.toml.",
            file=sys.stderr,
        )
        return EXIT_BLOCKED
    specs = [
        r.suggestion if r.requested_version is None else spec
        for r, spec in zip(results, args.packages, strict=True)
    ]
    command = ["uv", "add", *args.uv_args, *specs]
    print("\n$ " + " ".join(command))
    return subprocess.run(command, check=False).returncode  # noqa: S603  # nosec B603


# --- audit --------------------------------------------------------------------
def _non_registry_warnings(packages: Sequence[LockedPackage]) -> list[str]:
    return [
        f"⚠ {pkg.name} is installed from {pkg.source_kind} source ({pkg.source}); "
        "registry checks do not apply"
        for pkg in packages
        if not pkg.is_registry and pkg.source_kind not in {"editable", "virtual"}
    ]


def _vuln_batch(ctx: VetContext, packages: Sequence[LockedPackage]) -> list[str]:
    pins = [(p.name, p.version) for p in packages if p.is_registry]
    hits = ctx.osv.query_batch(pins)
    lines = []
    for (name, version), ids in sorted(hits.items()):
        active = [i for i in ids if not ctx.policy.vulnerability_is_ignored(i)]
        if active:
            lines.append(f"✗ {name}=={version}: {', '.join(active)}")
    return lines


def cmd_audit(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    lock_path = Path(args.lock)
    current = read_lock(lock_path)
    packages = list(current.values())

    if args.changed:
        previous = lock_at_ref(args.base, lock_path) or {}
        diff = diff_locks(previous, current)
        targets = [p for p in diff.to_vet if p.is_registry]
        print(
            f"Lock diff vs {args.base}: +{len(diff.added)} added, "
            f"~{len(diff.upgraded)} upgraded, -{len(diff.removed)} removed\n"
        )
    else:
        direct = direct_dependencies(Path(args.pyproject))
        targets = [p for p in packages if p.is_registry and (args.all or p.name in direct)]

    results = [vet_package(p.spec, ctx) for p in targets]
    if results:
        print(_render(results, args.format, verbose=args.verbose))

    problems = _non_registry_warnings(packages)
    try:
        vulnerable = _vuln_batch(ctx, packages)
    except NetworkError as exc:
        vulnerable = (
            [f"✗ OSV batch query failed: {exc}"] if ctx.policy.fail_on_network_error else []
        )
    if problems or vulnerable:
        print("\nLockfile-wide findings:")
        print("\n".join([*problems, *vulnerable]))

    blocked = _exit_code(results) != EXIT_OK or bool(
        vulnerable and ctx.policy.block_on_vulnerability
    )
    return EXIT_BLOCKED if blocked else EXIT_OK


# --- outdated -----------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class OutdatedRow:
    name: str
    current: str
    latest_allowed: str
    bump: str
    vulnerable: tuple[str, ...]
    direct: bool


def collect_outdated(
    ctx: VetContext, packages: Sequence[LockedPackage], direct: frozenset[str]
) -> list[OutdatedRow]:
    cutoff = ctx.now - timedelta(days=ctx.policy.min_version_age_days)
    vulns = ctx.osv.query_batch([(p.name, p.version) for p in packages])
    rows: list[OutdatedRow] = []
    for pkg in packages:
        info = ctx.pypi.fetch(pkg.name)
        current = try_parse_version(pkg.version)
        latest = info.latest_stable_before(cutoff) if info else None
        latest_parsed = latest.parsed if latest else None
        bump = bump_kind(current, latest_parsed) if current and latest_parsed else "unknown"
        vulnerable = vulns.get((pkg.name, pkg.version), ())
        if bump != "none" or vulnerable:
            rows.append(
                OutdatedRow(
                    pkg.name,
                    pkg.version,
                    latest.version if latest else "?",
                    bump,
                    vulnerable,
                    pkg.name in direct,
                )
            )
    order = {"major": 0, "minor": 1, "patch": 2, "unknown": 3, "none": 4}
    return sorted(rows, key=lambda r: (not r.vulnerable, order[r.bump], r.name))


def _run(command: list[str]) -> int:
    print("$ " + " ".join(command))
    return subprocess.run(command, check=False).returncode  # noqa: S603  # nosec B603


def _apply_upgrades(
    ctx: VetContext, rows: Sequence[OutdatedRow], *, security_only: bool, run_tests: bool
) -> int:
    cutoff = (ctx.now - timedelta(days=ctx.policy.min_version_age_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    if security_only:
        names = [r.name for r in rows if r.vulnerable]
        if not names:
            print("No vulnerable pins; nothing to upgrade.")
            return EXIT_OK
        command = [
            "uv",
            "lock",
            "--exclude-newer",
            cutoff,
            *(arg for n in names for arg in ("--upgrade-package", n)),
        ]
    else:
        command = ["uv", "lock", "--upgrade", "--exclude-newer", cutoff]
    for step in (command, ["uv", "sync"], *([["uv", "run", "pytest", "-q"]] if run_tests else [])):
        if (code := _run(step)) != 0:
            return code
    return EXIT_OK


def cmd_outdated(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    lock = read_lock(Path(args.lock))
    direct = direct_dependencies(Path(args.pyproject))
    packages = [p for p in lock.values() if p.is_registry and (args.all or p.name in direct)]
    try:
        rows = collect_outdated(ctx, packages, direct)
    except NetworkError as exc:
        print(f"Could not query registries: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not rows:
        print("All pins are current and free of known advisories.")
        return EXIT_OK
    table = render_table(
        ["Package", "Pinned", "Latest allowed", "Bump", "Advisories", "Direct"],
        [
            [
                r.name,
                r.current,
                r.latest_allowed,
                r.bump,
                ", ".join(r.vulnerable) or "-",
                "yes" if r.direct else "no",
            ]
            for r in rows
        ],
        markdown=args.format == "markdown",
    )
    print(table)
    vulnerable = [r for r in rows if r.vulnerable]
    print(f"\n{len(rows)} outdated, {len(vulnerable)} with security advisories.")

    if args.apply:
        return _apply_upgrades(ctx, rows, security_only=args.security_only, run_tests=args.test)
    return EXIT_BLOCKED if vulnerable and args.fail_on_vulnerable else EXIT_OK


# --- parser -------------------------------------------------------------------
def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", help="path to depguard.toml (default: ./depguard.toml)")
    parser.add_argument("--offline", action="store_true", help="use cached responses only")
    parser.add_argument("--no-cache", action="store_true", help="bypass the on-disk cache")
    parser.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    parser.add_argument("-v", "--verbose", action="store_true", help="show passing checks too")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="depguard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    vet = sub.add_parser("vet", help="check packages against the policy without installing")
    vet.add_argument("packages", nargs="+", metavar="PKG[==VERSION]")
    _common(vet)
    vet.set_defaults(func=cmd_vet)

    add = sub.add_parser("add", help="vet, then `uv add` the packages")
    add.add_argument("packages", nargs="+", metavar="PKG[==VERSION]")
    add.add_argument(
        "--uv-args", nargs="*", default=[], help="extra args for uv add, e.g. --uv-args --group dev"
    )
    _common(add)
    add.set_defaults(func=cmd_add)

    audit = sub.add_parser(
        "audit", help="vet the lockfile: policy on direct deps, OSV on every pin"
    )
    audit.add_argument(
        "--changed", action="store_true", help="only vet packages added/upgraded vs --base"
    )
    audit.add_argument("--base", default="HEAD", help="git ref to diff the lockfile against")
    audit.add_argument(
        "--all", action="store_true", help="apply policy checks to transitive deps too"
    )
    audit.add_argument("--lock", default=str(LOCK_PATH))
    audit.add_argument("--pyproject", default="pyproject.toml")
    _common(audit)
    audit.set_defaults(func=cmd_audit)

    outdated = sub.add_parser("outdated", help="report (and optionally apply) available upgrades")
    outdated.add_argument("--all", action="store_true", help="include transitive deps")
    outdated.add_argument("--apply", action="store_true", help="run uv lock --upgrade && uv sync")
    outdated.add_argument(
        "--security-only", action="store_true", help="with --apply: only upgrade vulnerable pins"
    )
    outdated.add_argument("--test", action="store_true", help="with --apply: run pytest afterwards")
    outdated.add_argument(
        "--fail-on-vulnerable", action="store_true", help="exit 1 when any pin has an advisory"
    )
    outdated.add_argument("--lock", default=str(LOCK_PATH))
    outdated.add_argument("--pyproject", default="pyproject.toml")
    _common(outdated)
    outdated.set_defaults(func=cmd_outdated)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (NetworkError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
