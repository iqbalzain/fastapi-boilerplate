# ADR 0001 — uv with a committed, hash-pinned lockfile

**Status**: accepted · 2026-10-31

## Context
Reproducible, auditable dependency resolution is a prerequisite for supply-chain policy.

## Decision
Use `uv` for resolution/installation. Commit `uv.lock`; install with `--frozen` in Docker and CI.
Pin the index explicitly (`[[tool.uv.index]]`) with `index-strategy = "first-index"` to prevent
dependency confusion through transitive index selection.

## Consequences
* Same bytes everywhere; the audited lock is what ships.
* `--exclude-newer` lets the upgrade path honour the release cooldown natively.
* Contributors need uv (installed by `make install` instructions); pip workflows are unsupported.
