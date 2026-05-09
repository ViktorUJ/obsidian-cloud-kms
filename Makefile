# Obsidian Cloud KMS Encryption Plugin — Build System
# Usage: make <target>
# Run `make help` to see all available targets.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Docker image for reproducible builds
DOCKER_IMAGE := obsidian-cloud-kms-builder
DOCKER_TAG := latest
DOCKER_RUN := docker run --rm -v $(CURDIR):/app -w /app $(DOCKER_IMAGE):$(DOCKER_TAG)

# Output artifacts
DIST_DIR := dist
ARTIFACTS := main.js manifest.json

# ─────────────────────────────────────────────────────────────────────────────
# Local targets
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: install
install: ## Install dependencies
	npm ci

.PHONY: build
build: ## Build plugin (production)
	node esbuild.config.mjs production

.PHONY: dev
dev: ## Build plugin (dev, watch mode)
	node esbuild.config.mjs

.PHONY: test
test: ## Run all tests
	npx vitest --run

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	npx vitest

.PHONY: test-property
test-property: ## Run only property-based tests
	npx vitest --run tests/property

.PHONY: lint
lint: ## Run ESLint
	npx eslint src/ tests/ --max-warnings 0

.PHONY: lint-fix
lint-fix: ## Run ESLint with auto-fix
	npx eslint src/ tests/ --fix

.PHONY: typecheck
typecheck: ## Run TypeScript type checking (no emit)
	npx tsc --noEmit

.PHONY: audit
audit: ## Run npm audit for security vulnerabilities (high + critical)
	npm audit --audit-level=high

.PHONY: audit-fix
audit-fix: ## Run npm audit fix
	npm audit fix

.PHONY: security
security: audit ## Run full security scan (audit + snyk if available)
	@command -v snyk >/dev/null 2>&1 && snyk test --severity-threshold=high || echo "snyk not installed, skipping. Install: npm i -g snyk"

.PHONY: check
check: typecheck lint test audit ## Run all checks (typecheck + lint + test + audit)

.PHONY: ci
ci: install check build ## Full CI pipeline (install + check + build)

.PHONY: clean
clean: ## Remove build artifacts
	rm -f main.js main.js.map
	rm -rf $(DIST_DIR) coverage .vitest

.PHONY: release
release: clean ci ## Build release artifacts
	@mkdir -p $(DIST_DIR)
	@cp main.js manifest.json $(DIST_DIR)/
	@test -f styles.css && cp styles.css $(DIST_DIR)/ || true
	@echo "Release artifacts in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/

# ─────────────────────────────────────────────────────────────────────────────
# Docker targets (reproducible builds)
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: docker-build-image
docker-build-image: ## Build the Docker builder image
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: docker-install
docker-install: docker-build-image ## Install deps in Docker
	$(DOCKER_RUN) npm ci

.PHONY: docker-build
docker-build: docker-build-image ## Build plugin in Docker
	$(DOCKER_RUN) make ci

.PHONY: docker-test
docker-test: docker-build-image ## Run tests in Docker
	$(DOCKER_RUN) make test

.PHONY: docker-lint
docker-lint: docker-build-image ## Run linter in Docker
	$(DOCKER_RUN) make lint

.PHONY: docker-security
docker-security: docker-build-image ## Run security scan in Docker
	$(DOCKER_RUN) make security

.PHONY: docker-check
docker-check: docker-build-image ## Run all checks in Docker
	$(DOCKER_RUN) make check

.PHONY: docker-release
docker-release: docker-build-image ## Build release artifacts in Docker
	$(DOCKER_RUN) make release

.PHONY: docker-shell
docker-shell: docker-build-image ## Open shell in Docker container
	docker run --rm -it -v $(CURDIR):/app -w /app $(DOCKER_IMAGE):$(DOCKER_TAG) bash

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@echo "Obsidian Cloud KMS Encryption — Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make ci              # Full local CI pipeline"
	@echo "  make docker-release  # Reproducible release build in Docker"
	@echo "  make security        # Security audit"
