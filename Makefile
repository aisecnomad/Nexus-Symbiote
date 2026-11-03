.DEFAULT_GOAL := help

# ── Development ──────────────────────────────────────────────

.PHONY: install
install: install-locked ## Install the reviewed locked development environment

.PHONY: install-locked
install-locked: ## Install from the locked CI dependency set
	python -m pip install --require-hashes -r requirements-ci.lock
	python -m pip install --no-deps --no-build-isolation -e .

# ── Quality ──────────────────────────────────────────────────

.PHONY: lint
lint: ## Run ruff linter
	ruff check src tests scripts

.PHONY: format-check
format-check: ## Check code formatting with ruff
	ruff format --check src tests scripts

.PHONY: typecheck
typecheck: ## Run mypy strict type checking
	mypy src/nexus_symbiote scripts

.PHONY: quality
quality: lint format-check typecheck workflow-check hygiene ## Run all quality checks

.PHONY: workflow-check
workflow-check: ## Validate pinned workflow references and shell inputs
	python scripts/check_workflows.py

.PHONY: hygiene
hygiene: ## Check tracked source, links, versions and vendor digests
	python scripts/check_repository_hygiene.py

# ── Testing ──────────────────────────────────────────────────

.PHONY: test
test: ## Run the test suite
	python -m pytest

.PHONY: test-verbose
test-verbose: ## Run the test suite with verbose output
	python -m pytest -vv --durations=20

.PHONY: coverage
coverage: ## Run tests with coverage reporting
	python -m pytest --cov=nexus_symbiote --cov-branch --cov-report=term-missing --cov-report=json:coverage.json
	python scripts/check_coverage.py coverage.json

.PHONY: security-regressions
security-regressions: ## Run the committed security regression contracts
	PYTHONPATH=src python scripts/check_security_regressions.py --out security-regressions.json

# ── Build ────────────────────────────────────────────────────

.PHONY: build
build: ## Build sdist and wheel distributions
	python -m build --no-isolation

.PHONY: check-dist
check-dist: ## Validate built distributions with twine
	python -m twine check dist/*

.PHONY: wheel-smoke
wheel-smoke: build ## Check the exact wheel in a temporary locked environment
	@set -eu; smoke_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$smoke_dir"' EXIT; \
	python -m venv "$$smoke_dir"; \
	"$$smoke_dir/bin/python" -m pip install --require-hashes -r requirements-ci.lock; \
	"$$smoke_dir/bin/python" -m pip install --no-index --no-deps dist/*.whl; \
	"$$smoke_dir/bin/python" -I scripts/check_wheel_security.py dist/*.whl

# ── Clean ────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	find src tests scripts -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .coverage .mypy_cache .pytest_cache .ruff_cache
	rm -f coverage.json security-regressions.json

# ── Help ─────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
