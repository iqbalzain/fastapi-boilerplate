# Security policy

## Reporting a vulnerability
Email **security@your-org.example** with a description, reproduction steps and impact. You will
receive an acknowledgement within 2 business days and a remediation plan within 7. Please do not
open public issues for security reports.

## Supported versions
The `main` branch and the latest tagged release.

## Dependency advisories
Dependencies are audited on every PR and weekly (`.github/workflows/dependency-health.yml`), which
opens a `security`-labelled issue when a pinned version has an advisory. Policy and exceptions are
in `depguard.toml`; see `docs/dependency-governance.md`.
