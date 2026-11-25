.DEFAULT_GOAL := help
PYTHON_FLOOR ?= python3.11

# ── Development ──────────────────────────────────────────────

.PHONY: install
install: install-locked ## Install the reviewed locked development environment

.PHONY: install-locked
install-locked: ## Install from the locked CI dependency set
	python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock
	python -m pip install --no-deps --no-build-isolation -e .
	python -m pip check

# ── Dependency locks ─────────────────────────────────────────

.PHONY: lock
lock: ## Regenerate the CI, Action and floor locks from pyproject.toml (pinned uv, needs PyPI)
	python scripts/check_locks.py --regenerate

.PHONY: lock-upgrade
lock-upgrade: ## Upgrade every locked package to the newest release at least a week old
	python scripts/check_locks.py --regenerate --upgrade

.PHONY: lock-check
lock-check: ## Check the locks against pyproject.toml and each other, offline
	python scripts/check_locks.py

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
quality: lint format-check typecheck workflow-check hygiene lock-check ## Run all quality checks

.PHONY: workflow-check
workflow-check: ## Validate pinned workflow references and shell inputs
	python scripts/check_workflows.py

.PHONY: hygiene
hygiene: ## Check tracked source, links, versions and vendor digests
	python scripts/check_repository_hygiene.py

# ── Testing ──────────────────────────────────────────────────

# One worker per core, as in CI. Each worker starts with a contiguous share of the suite in
# collection order and an idle one takes tests from the longest queue, so slow files do not
# hold a core idle. `make test PYTEST_PARALLEL=` runs the suite in one process.
PYTEST_PARALLEL = -n auto --dist worksteal

.PHONY: test
test: ## Run the test suite; a skip other than a host file-system one (or a missing pip outside CI) fails it
	python -m pytest $(PYTEST_PARALLEL) --strict-skips

.PHONY: test-verbose
test-verbose: ## Run the test suite with verbose output
	python -m pytest $(PYTEST_PARALLEL) -vv --durations=20 --strict-skips

.PHONY: test-floor
test-floor: ## Run the suite on Python 3.11 with each runtime dependency at its declared floor, without the locked_only tests
	@set -eu; floor_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$floor_dir"' EXIT; \
	$(PYTHON_FLOOR) -m venv "$$floor_dir"; \
	"$$floor_dir/bin/python" -m pip install --require-hashes --only-binary=:all: -r requirements-floor.lock; \
	"$$floor_dir/bin/python" -m pip install --no-deps --no-build-isolation -e .; \
	"$$floor_dir/bin/python" -m pip check; \
	"$$floor_dir/bin/python" -m pytest $(PYTEST_PARALLEL) --strict-skips -m "not locked_only"

.PHONY: coverage
coverage: ## Run tests with coverage reporting
	python -m pytest $(PYTEST_PARALLEL) --strict-skips --cov=nexus_symbiote --cov=scripts --cov-branch --cov-report=term-missing --cov-report=json:coverage.json
	python scripts/check_coverage.py coverage.json

.PHONY: security-regressions
security-regressions: ## Run the committed security regression contracts
	PYTHONPATH=src python scripts/check_security_regressions.py --out security-regressions.json

.PHONY: precision
precision: ## Run the drift-regression gate and the class recall floors on a fresh benchmark scan
	PYTHONPATH=src python scripts/check_precision_gate.py --fresh --out precision-gate.json

.PHONY: fuzz-smoke
fuzz-smoke: ## Exercise bounded parser readers against the deterministic fuzz corpus
	PYTHONPATH=src python scripts/fuzz_parsers.py --iterations 64

.PHONY: check
check: quality coverage security-regressions precision fuzz-smoke ## Run the offline subset of the required CI checks
	$(MAKE) clean-dist
	$(MAKE) build
	$(MAKE) check-dist

# ── Build ────────────────────────────────────────────────────

.PHONY: build
build: ## Build sdist and wheel distributions
	python -m build --no-isolation

.PHONY: check-dist
check-dist: ## Validate built distributions with twine
	python -m twine check --strict dist/*

.PHONY: wheel-smoke
wheel-smoke: ## Build afresh and check the exact wheel in a temporary locked environment
	$(MAKE) clean-dist
	$(MAKE) build
	@set -eu; smoke_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$smoke_dir"' EXIT; \
	python -m venv "$$smoke_dir"; \
	"$$smoke_dir/bin/python" -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock; \
	"$$smoke_dir/bin/python" -m pip install --no-index --no-deps --only-binary=:all: dist/*.whl; \
	"$$smoke_dir/bin/python" -I scripts/check_wheel_security.py dist/*.whl

.PHONY: image-smoke
image-smoke: ## Build afresh, then build the container image from that wheel and run it offline (needs Docker)
	$(MAKE) clean-dist
	$(MAKE) build
	python -I -S scripts/check_image.py dist

# ── Clean ────────────────────────────────────────────────────

.PHONY: clean-dist
clean-dist: ## Remove built distributions so check-dist inspects only a fresh build
	rm -rf dist/

.PHONY: clean
clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	find src tests scripts -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .coverage .coverage.* htmlcov .hypothesis .mypy_cache .pytest_cache .ruff_cache
	rm -f coverage.json security-regressions.json precision-gate.json benchmark-results.json

# ── Help ─────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
