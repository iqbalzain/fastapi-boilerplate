"""Render vet/audit/outdated results as text, Markdown or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING

from depguard.checks import Level

if TYPE_CHECKING:
    from collections.abc import Sequence

    from depguard.checks import VetResult


def render_vet_text(results: Sequence[VetResult], *, verbose: bool = False) -> str:
    lines: list[str] = []
    for result in results:
        version = result.resolved_version or "?"
        lines.append(f"{result.worst.symbol} {result.package}=={version}  [{result.worst.name}]")
        for finding in result.findings:
            if finding.level is Level.PASS and not verbose:
                continue
            lines.append(f"    {finding.level.symbol} {finding.rule}: {finding.message}")
        if (
            not result.failed
            and result.suggestion != result.package
            and result.requested_version is None
        ):
            lines.append(f"    → install with: {result.suggestion}")
    failed = sum(1 for r in results if r.failed)
    lines.append("")
    lines.append(f"{len(results)} package(s) checked, {failed} blocked.")
    return "\n".join(lines)


def render_vet_markdown(results: Sequence[VetResult]) -> str:
    rows = ["| Package | Version | Result | Notes |", "|---|---|---|---|"]
    for result in results:
        notes = "<br>".join(
            f"{f.level.symbol} {f.rule}: {f.message}"
            for f in result.findings
            if f.level >= Level.WARN
        )
        rows.append(
            f"| `{result.package}` | {result.resolved_version or '?'} "
            f"| {result.worst.symbol} {result.worst.name} | {notes} |"
        )
    return "\n".join(rows)


def render_vet_json(results: Sequence[VetResult]) -> str:
    payload = [
        {
            **asdict(result),
            "worst": result.worst.name,
            "findings": [{**asdict(f), "level": f.level.name} for f in result.findings],
        }
        for result in results
    ]
    return json.dumps(payload, indent=2)


def render_table(headers: Sequence[str], rows: Sequence[Sequence[str]], *, markdown: bool) -> str:
    if markdown:
        out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
        out.extend("| " + " | ".join(row) + " |" for row in rows)
        return "\n".join(out)
    widths = [
        max(len(str(cell)) for cell in column) for column in zip(headers, *rows, strict=False)
    ]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    out = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    out.extend(fmt.format(*row) for row in rows)
    return "\n".join(out)
