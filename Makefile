.DEFAULT_GOAL := help
# Override when uv is not first on PATH, e.g. make test UV=~/.local/bin/uv
UV ?= uv
PY := $(UV) run
DEPGUARD := PYTHONPATH=tools $(PY) python -m depguard

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install all dependencies (locked) and git hooks
	$(UV) sync --frozen --all-groups
	$(PY) pre-commit install --install-hooks

dev: ## Run the API with hot reload
	$(PY) uvicorn app.main:create_app --factory --reload --port 8000

test: ## Run the test-suite with coverage gate
	$(PY) pytest

lint: ## Ruff lint + format check, mypy, bandit
	$(PY) ruff check .
	$(PY) ruff format --check .
	$(PY) mypy
	$(PY) bandit -c pyproject.toml -r src tools -q

fmt: ## Auto-format and fix lint
	$(PY) ruff format .
	$(PY) ruff check --fix .

migrate: ## Apply database migrations
	$(PY) alembic upgrade head

migration: ## Autogenerate a migration: make migration m="add widgets"
	$(PY) alembic revision --autogenerate -m "$(m)"

# ---------------------------------------------------------------- dependencies
add: ## Vet then add a package: make add PKG=httpx [ARGS="--group dev"]
	$(DEPGUARD) add $(PKG) --uv-args $(ARGS)

vet: ## Vet packages without installing: make vet PKG="httpx rich"
	$(DEPGUARD) vet $(PKG)

audit: ## Policy + vulnerability audit of the lockfile
	$(DEPGUARD) audit
	$(UV) export --no-dev --no-hashes -q -o .depguard-cache/requirements.txt
	$(PY) pip-audit --strict --progress-spinner off -r .depguard-cache/requirements.txt

outdated: ## Show upgrades available (cooldown-aware) and advisories
	$(DEPGUARD) outdated

upgrade: ## Apply all policy-compliant upgrades, then run tests
	$(DEPGUARD) outdated --apply --test

upgrade-security: ## Upgrade only pins with known advisories
	$(DEPGUARD) outdated --apply --security-only --test

# ------------------------------------------------------------------ containers
up: ## Start postgres, redis and the API
	docker compose up --build -d

down: ## Stop containers
	docker compose down -v

.PHONY: help install dev test lint fmt migrate migration add vet audit outdated upgrade upgrade-security up down
