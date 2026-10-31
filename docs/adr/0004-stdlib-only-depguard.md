# ADR 0004 — Dependency governance as a stdlib-only tool in the repo

**Status**: accepted · 2026-10-31

## Context
We need to vet packages *before* they are installed, from an agent hook, from pre-commit and from
CI, and the checker must not itself be a supply-chain risk or require the environment it polices.

## Decision
`tools/depguard` uses only the standard library (`urllib`, `tomllib`, `difflib`-style heuristics)
and talks to PyPI JSON, the PyPI integrity API and OSV directly. Policy is data (`depguard.toml`),
exceptions are explicit and expiring, and network failures fail closed.

## Alternatives considered
* `pip-audit` / `safety` alone: advisories only, nothing about authenticity, age, cooldown or licence. Kept `pip-audit` in CI as a second source.
* Socket / Snyk / Dependabot: valuable but SaaS-bound; the template must work offline-first and inside any org. Renovate config is shipped as an opt-in.
* `uv`'s `exclude-newer`: used for upgrades, but it cannot express typosquat/age/licence rules.

## Consequences
* Zero install cost; runs in the Claude Code hook with plain `python3`.
* Heuristics (top-package list, licence substrings) need occasional curation.
