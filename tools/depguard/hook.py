"""Claude Code ``PreToolUse`` hook: vet packages before any install command runs.

Reads the hook payload from stdin, finds ``uv add`` / ``pip install`` style
commands, and vets every named package. Exit code 2 blocks the tool call and
feeds the reason back to the agent. Set ``DEPGUARD_SKIP=1`` to bypass (logged).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path

from depguard.checks import vet_package
from depguard.http import JsonClient, NetworkError
from depguard.osv import OSVClient
from depguard.policy import load_policy
from depguard.pypi import PyPIClient
from depguard.report import render_vet_text

INSTALLERS: tuple[tuple[str, ...], ...] = (
    ("uv", "add"),
    ("uv", "pip", "install"),
    ("pip", "install"),
    ("pip3", "install"),
    ("python", "-m", "pip", "install"),
    ("python3", "-m", "pip", "install"),
    ("poetry", "add"),
    ("pipx", "install"),
)
_FLAGS_WITH_VALUE = {
    "--group",
    "--index",
    "--index-url",
    "--extra-index-url",
    "-i",
    "--python",
    "-p",
    "--constraint",
    "-c",
    "--target",
    "-t",
    "--extra",
    "--optional",
    "--source",
    "--rev",
    "--tag",
    "--branch",
    "--package",
    "--project",
    "--directory",
}
_UNVETTABLE_FLAGS = {"-r", "--requirement", "-e", "--editable"}
_SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")


def extract_install_specs(command: str) -> tuple[list[str], list[str]]:
    """Return ``(package_specs, unvettable_reasons)`` found in a shell command."""
    specs: list[str] = []
    reasons: list[str] = []
    for segment in _SEGMENT_SPLIT.split(command):
        try:
            tokens = shlex.split(segment)
        except ValueError:
            continue
        for prefix in INSTALLERS:
            if tuple(tokens[: len(prefix)]) == prefix:
                specs_, reasons_ = _parse_args(tokens[len(prefix) :])
                specs.extend(specs_)
                reasons.extend(reasons_)
                break
    return specs, reasons


def _parse_args(tokens: list[str]) -> tuple[list[str], list[str]]:
    specs: list[str] = []
    reasons: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in _UNVETTABLE_FLAGS:
            reasons.append(f"'{token}' installs from a file/path that cannot be vetted here")
            skip_next = True
            continue
        if token in _FLAGS_WITH_VALUE:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        if (
            "://" in token
            or token.startswith(("git+", ".", "/", "~"))
            or token.endswith((".whl", ".tar.gz"))
        ):
            reasons.append(f"{token!r} is a non-registry source; add it via a reviewed PR instead")
            continue
        specs.append(token)
    return specs, reasons


def main() -> int:
    if os.environ.get("DEPGUARD_SKIP") == "1":
        print("depguard: skipped via DEPGUARD_SKIP=1", file=sys.stderr)
        return 0
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    if payload.get("tool_name") != "Bash":
        return 0
    command = str(payload.get("tool_input", {}).get("command", ""))
    specs, reasons = extract_install_specs(command)
    if not specs and not reasons:
        return 0

    policy_path = Path(payload.get("cwd", ".")) / "depguard.toml"
    policy = load_policy(policy_path if policy_path.exists() else None)
    from depguard.checks import VetContext

    ctx = VetContext(policy=policy, pypi=PyPIClient(JsonClient()), osv=OSVClient())
    try:
        results = [vet_package(spec, ctx) for spec in specs]
    except NetworkError as exc:
        print(f"depguard: could not verify packages ({exc}); blocking install.", file=sys.stderr)
        return 2

    print(render_vet_text(results), file=sys.stderr)
    for reason in reasons:
        print(f"✗ {reason}", file=sys.stderr)
    if reasons or any(r.failed for r in results):
        print(
            "\ndepguard BLOCKED this install. Fix the findings, pin the suggested version, "
            "or record an exception in depguard.toml.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
