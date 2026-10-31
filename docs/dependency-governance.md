# Dependency governance

Third-party code is the largest attack surface this template cannot control. `tools/depguard`
makes the policy in `depguard.toml` executable and enforces it at four points.

## Enforcement points

| When | What runs | Blocks? |
|---|---|---|
| Claude Code runs `uv add` / `pip install` | `.claude/settings.json` PreToolUse hook → `depguard.hook` | yes (exit 2, reasons fed back to the agent) |
| A developer adds a package | `make add PKG=…` → `depguard add` → `uv add` | yes |
| `git commit` touching `pyproject.toml` / `uv.lock` | pre-commit `depguard audit --changed` + `uv-lock` sync check | yes |
| Pull request | CI `dependencies` job: `audit --changed` vs base, full OSV audit, `pip-audit` | yes |
| Weekly (Mon 06:00 UTC) | `dependency-health.yml`: full audit → issue on advisories; `outdated --apply --test` → upgrade PR | PR only if tests pass |

`DEPGUARD_SKIP=1` bypasses the hook for emergencies; the bypass is printed and the commit/PR
checks still run.

## What is checked

| Rule | Default | Rationale |
|---|---|---|
| `denied_package` | list in policy | known-malicious or deprecated-insecure names (e.g. `python-jose`) |
| `typosquat` | edit distance ≤ 2 to a top package, homoglyph collapse, affix variants | `requets`, `ur11ib3`, `python-requests` |
| `exists` | — | registry 404 or unknown version |
| `min_project_age_days` | 90 | brand-new projects are the common malware vector |
| `min_release_count` | 3 | single-release drops have no maintenance history |
| `max_days_since_last_release` | 730 (warn) | abandoned packages do not get security fixes |
| `min_version_age_days` | 7 | **cooldown**: compromised-maintainer releases are usually pulled within days. Unpinned requests resolve to the newest *cooled-down* version |
| `yanked` | — | maintainers withdrew the release |
| `require_wheel` | true | sdist-only installs execute `setup.py` on the developer's machine |
| `license` | allow/deny substrings | copyleft/SSPL exposure |
| `repository_url` | warn | no public source to audit |
| `python_version` | 3.12 | `requires-python` compatibility |
| `max_direct_dependencies` | 30 (warn) | transitive bloat |
| `provenance` | info | PEP 740 attestation from Trusted Publishing present or not |
| `vulnerability` | block | any OSV advisory for the exact pinned version, unless ignored with an expiring reason |

Network failures **fail closed** (`fail_on_network_error = true`): an unverifiable package is not
installed.

## Exceptions

Every exception is explicit, attributed and time-boxed:

```toml
[[exceptions]]
package = "our-internal-sdk"
rule = "min_project_age_days"
reason = "First-party package, reviewed by @security 2026-10-30"
expires = "2027-01-31"

[vulnerabilities]
ignore = [{ id = "GHSA-xxxx", reason = "vulnerable code path (XML parsing) is not used", expires = "2026-12-31" }]
```

Expired exceptions silently stop applying, so the rule fails again and forces a re-review.
Add a package to `[packages].trusted` only for well-known foundations (it skips heuristics, never
vulnerability/yank/licence checks).

## Keeping current

```bash
make outdated            # table: pinned → latest allowed (cooldown-aware), bump kind, advisories
make upgrade             # uv lock --upgrade --exclude-newer <now-7d> → uv sync → pytest
make upgrade-security    # only pins with advisories, via --upgrade-package
```

`--exclude-newer` makes uv itself respect the cooldown during resolution, so the upgrade can never
pick a version depguard would reject. The weekly workflow does the same and opens a PR; if you
prefer continuous PRs, enable Renovate with the shipped `renovate.json` (`minimumReleaseAge: 7 days`,
security updates exempt from the cooldown).

## Design notes

* **Stdlib only.** depguard imports nothing outside the standard library, so it runs before
  `uv sync`, cannot be compromised by the dependencies it polices, and is itself not a dependency.
* **Two advisory sources.** depguard queries OSV directly; CI also runs `pip-audit` (PyPI advisory DB
  via OSV) for defence in depth.
* **Cache.** Responses are cached in `.depguard-cache/` (6 h PyPI, 1 h OSV) to stay polite and fast;
  `--no-cache` forces fresh data, `--offline` uses cache only.
* **Hash-locked installs.** `uv.lock` records hashes; Docker and CI use `--frozen`, so what was
  vetted is what is installed.
