# Contributing

1. `make install` (uv + pre-commit hooks).
2. Branch from `main`; conventional commits (`feat:`, `fix:`, `chore(deps):` …).
3. Tests first. `make test` must pass with ≥80% coverage; `make lint` must be clean.
4. New dependency? `make add PKG=…` only. Record any policy exception in `depguard.toml` with a
   reason and expiry, and explain it in the PR.
5. New setting? Add it to `Settings` **and** `.env.example`.
6. Security-relevant change (auth, input handling, headers, deps)? Mention it in the PR and update
   `docs/security.md` if a control changed.
7. Keep files under ~400 lines and functions under ~50; extract modules rather than growing them.
