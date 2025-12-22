# NetStress - Military-Grade Network Testing Framework
# Comprehensive Makefile for cross-platform development

# Project configuration
PROJECT_NAME := netstress
VERSION := $(shell python -c "import toml; print(toml.load('pyproject.toml')['project']['version'])")
PYTHON := python
PIP := pip
CARGO := cargo
DOCKER := docker

# Directories
SRC_DIR := core
NATIVE_DIR := native
RUST_DIR := $(NATIVE_DIR)/rust_engine
C_DIR := $(NATIVE_DIR)/c_driver
DOCS_DIR := docs
TESTS_DIR := tests
BUILD_DIR := build
DIST_DIR := dist

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
    SHARED_EXT := .so
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
    SHARED_EXT := .dylib
endif
ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    SHARED_EXT := .dll
endif

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[0;37m
NC := \033[0m # No Color

# Default target
.DEFAULT_GOAL := help

# Help target
.PHONY: help
help: ## Show this help message
	@echo "$(CYAN)NetStress - Military-Grade Network Testing Framework$(NC)"
	@echo "$(YELLOW)Version: $(VERSION)$(NC)"
	@echo "$(YELLOW)Platform: $(PLATFORM)$(NC)"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(BLUE)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Installation targets
.PHONY: install install-dev install-native install-deps
install: ## Install NetStress in production mode
	@echo "$(GREEN)Installing NetStress...$(NC)"
	$(PIP) install -e .
	@echo "$(GREEN)Installation complete!$(NC)"

install-dev: ## Install NetStress in development mode with all dependencies
	@echo "$(GREEN)Installing NetStress in development mode...$(NC)"
	$(PIP) install -e .
	$(PIP) install -r requirements-dev.txt
	@echo "$(GREEN)Development installation complete!$(NC)"

install-native: ## Install with native components (Rust + C)
	@echo "$(GREEN)Installing NetStress with native components...$(NC)"
	$(MAKE) build-native
	$(PIP) install -e .
	@echo "$(GREEN)Native installation complete!$(NC)"

install-deps: ## Install Python dependencies
	@echo "$(GREEN)Installing Python dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)Dependencies installed!$(NC)"

# Build targets
.PHONY: build build-native build-rust build-c build-python clean-build
build: build-python ## Build Python package

build-native: build-rust build-c ## Build all native components
	@echo "$(GREEN)Native components built successfully!$(NC)"

build-rust: ## Build Rust engine
	@echo "$(GREEN)Building Rust engine...$(NC)"
	@if [ -d "$(RUST_DIR)" ]; then \
		cd $(RUST_DIR) && $(CARGO) build --release; \
		echo "$(GREEN)Rust engine built successfully!$(NC)"; \
	else \
		echo "$(YELLOW)Rust directory not found, skipping...$(NC)"; \
	fi

build-c: ## Build C driver
	@echo "$(GREEN)Building C driver...$(NC)"
	@if [ -d "$(C_DIR)" ] && [ -f "$(C_DIR)/Makefile" ]; then \
		cd $(C_DIR) && make; \
		echo "$(GREEN)C driver built successfully!$(NC)"; \
	else \
		echo "$(YELLOW)C driver not available, skipping...$(NC)"; \
	fi

build-python: ## Build Python package
	@echo "$(GREEN)Building Python package...$(NC)"
	$(PYTHON) -m build
	@echo "$(GREEN)Python package built successfully!$(NC)"

clean-build: ## Clean build artifacts
	@echo "$(GREEN)Cleaning build artifacts...$(NC)"
	rm -rf $(BUILD_DIR) $(DIST_DIR) *.egg-info
	@if [ -d "$(RUST_DIR)" ]; then cd $(RUST_DIR) && $(CARGO) clean; fi
	@if [ -d "$(C_DIR)" ] && [ -f "$(C_DIR)/Makefile" ]; then cd $(C_DIR) && make clean; fi
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "$(GREEN)Build artifacts cleaned!$(NC)"

# Testing targets
.PHONY: test test-unit test-integration test-properties test-cross-platform test-performance test-security
test: test-unit test-properties ## Run all tests

test-unit: ## Run unit tests
	@echo "$(GREEN)Running unit tests...$(NC)"
	$(PYTHON) -m pytest $(TESTS_DIR) -v --tb=short -x
	@echo "$(GREEN)Unit tests completed!$(NC)"

test-integration: ## Run integration tests
	@echo "$(GREEN)Running integration tests...$(NC)"
	$(PYTHON) -m pytest $(TESTS_DIR)/test_integration_*.py -v --tb=short
	@echo "$(GREEN)Integration tests completed!$(NC)"

test-properties: ## Run property-based tests
	@echo "$(GREEN)Running property-based tests...$(NC)"
	$(PYTHON) -m pytest $(TESTS_DIR)/test_properties.py -v --tb=short
	$(PYTHON) -m pytest $(TESTS_DIR)/test_*_properties.py -v --tb=short
	@echo "$(GREEN)Property-based tests completed!$(NC)"

test-cross-platform: ## Run cross-platform tests
	@echo "$(GREEN)Running cross-platform tests...$(NC)"
	$(PYTHON) -m pytest $(TESTS_DIR)/test_cross_platform_*.py -v --tb=short
	@echo "$(GREEN)Cross-platform tests completed!$(NC)"

test-performance: ## Run performance benchmarks
	@echo "$(GREEN)Running performance benchmarks...$(NC)"
	$(PYTHON) benchmarks/run_benchmarks.py
	@echo "$(GREEN)Performance benchmarks completed!$(NC)"

test-security: ## Run security tests
	@echo "$(GREEN)Running security tests...$(NC)"
	$(PYTHON) -m pytest $(TESTS_DIR)/test_security_*.py -v --tb=short
	@echo "$(GREEN)Security tests completed!$(NC)"

test-coverage: ## Run tests with coverage report
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	$(PYTHON) -m pytest --cov=$(SRC_DIR) --cov-report=html --cov-report=term
	@echo "$(GREEN)Coverage report generated in htmlcov/$(NC)"

# Code quality targets
.PHONY: lint format check-format check-types check-security check-all
lint: ## Run linting checks
	@echo "$(GREEN)Running linting checks...$(NC)"
	flake8 $(SRC_DIR) $(TESTS_DIR)
	pylint $(SRC_DIR)
	@if [ -d "$(RUST_DIR)" ]; then cd $(RUST_DIR) && $(CARGO) clippy -- -D warnings; fi
	@echo "$(GREEN)Linting completed!$(NC)"

format: ## Format code
	@echo "$(GREEN)Formatting code...$(NC)"
	black $(SRC_DIR) $(TESTS_DIR)
	isort $(SRC_DIR) $(TESTS_DIR)
	@if [ -d "$(RUST_DIR)" ]; then cd $(RUST_DIR) && $(CARGO) fmt; fi
	@echo "$(GREEN)Code formatting completed!$(NC)"

check-format: ## Check code formatting
	@echo "$(GREEN)Checking code formatting...$(NC)"
	black --check $(SRC_DIR) $(TESTS_DIR)
	isort --check-only $(SRC_DIR) $(TESTS_DIR)
	@if [ -d "$(RUST_DIR)" ]; then cd $(RUST_DIR) && $(CARGO) fmt --check; fi
	@echo "$(GREEN)Format check completed!$(NC)"

check-types: ## Run type checking
	@echo "$(GREEN)Running type checks...$(NC)"
	mypy $(SRC_DIR)
	@echo "$(GREEN)Type checking completed!$(NC)"

check-security: ## Run security checks
	@echo "$(GREEN)Running security checks...$(NC)"
	bandit -r $(SRC_DIR)
	safety check
	@echo "$(GREEN)Security checks completed!$(NC)"

check-all: check-format check-types lint check-security ## Run all code quality checks
	@echo "$(GREEN)All code quality checks completed!$(NC)"

# Documentation targets
.PHONY: docs docs-build docs-serve docs-clean
docs: docs-build ## Build documentation

docs-build: ## Build documentation
	@echo "$(GREEN)Building documentation...$(NC)"
	@if command -v sphinx-build >/dev/null 2>&1; then \
		sphinx-build -b html $(DOCS_DIR) $(DOCS_DIR)/_build/html; \
		echo "$(GREEN)Documentation built in $(DOCS_DIR)/_build/html$(NC)"; \
	else \
		echo "$(YELLOW)Sphinx not available, skipping documentation build$(NC)"; \
	fi

docs-serve: docs-build ## Serve documentation locally
	@echo "$(GREEN)Serving documentation at http://localhost:8000$(NC)"
	@cd $(DOCS_DIR)/_build/html && $(PYTHON) -m http.server 8000

docs-clean: ## Clean documentation build
	@echo "$(GREEN)Cleaning documentation build...$(NC)"
	rm -rf $(DOCS_DIR)/_build
	@echo "$(GREEN)Documentation build cleaned!$(NC)"

# Development targets
.PHONY: dev-setup dev-run dev-test dev-benchmark dev-profile
dev-setup: install-dev ## Set up development environment
	@echo "$(GREEN)Development environment setup complete!$(NC)"
	@echo "$(YELLOW)Run 'make dev-test' to verify installation$(NC)"

dev-run: ## Run NetStress in development mode
	@echo "$(GREEN)Running NetStress in development mode...$(NC)"
	$(PYTHON) -m netstress_cli --target 127.0.0.1 --port 80 --duration 10 --rate 1000

dev-test: ## Run quick development tests
	@echo "$(GREEN)Running development tests...$(NC)"
	$(PYTHON) -m pytest $(TESTS_DIR)/test_native_engine.py -v
	$(PYTHON) -c "from core.hardware.detector import HardwareProfile; print('Hardware detection:', HardwareProfile.detect().tier.name)"

dev-benchmark: ## Run quick performance benchmark
	@echo "$(GREEN)Running quick benchmark...$(NC)"
	$(PYTHON) benchmarks/quick_benchmark.py

dev-profile: ## Profile NetStress performance
	@echo "$(GREEN)Profiling NetStress performance...$(NC)"
	$(PYTHON) -m cProfile -o profile.stats -m netstress_cli --target 127.0.0.1 --port 80 --duration 5
	$(PYTHON) -c "import pstats; pstats.Stats('profile.stats').sort_stats('cumulative').print_stats(20)"

# Docker targets
.PHONY: docker-build docker-run docker-test docker-push docker-clean
docker-build: ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(NC)"
	$(DOCKER) build -t $(PROJECT_NAME):$(VERSION) .
	$(DOCKER) tag $(PROJECT_NAME):$(VERSION) $(PROJECT_NAME):latest
	@echo "$(GREEN)Docker image built successfully!$(NC)"

docker-run: ## Run NetStress in Docker
	@echo "$(GREEN)Running NetStress in Docker...$(NC)"
	$(DOCKER) run --rm -it $(PROJECT_NAME):latest --target 127.0.0.1 --port 80 --duration 10

docker-test: ## Test Docker image
	@echo "$(GREEN)Testing Docker image...$(NC)"
	$(DOCKER) run --rm $(PROJECT_NAME):latest --version
	$(DOCKER) run --rm $(PROJECT_NAME):latest --help

docker-push: ## Push Docker image to registry
	@echo "$(GREEN)Pushing Docker image...$(NC)"
	$(DOCKER) push $(PROJECT_NAME):$(VERSION)
	$(DOCKER) push $(PROJECT_NAME):latest

docker-clean: ## Clean Docker images
	@echo "$(GREEN)Cleaning Docker images...$(NC)"
	$(DOCKER) rmi $(PROJECT_NAME):$(VERSION) $(PROJECT_NAME):latest 2>/dev/null || true
	$(DOCKER) system prune -f

# Release targets
.PHONY: release release-check release-build release-upload release-tag
release: release-check release-build release-upload release-tag ## Create and upload release

release-check: ## Check if ready for release
	@echo "$(GREEN)Checking release readiness...$(NC)"
	@$(MAKE) check-all
	@$(MAKE) test
	@echo "$(GREEN)Release checks passed!$(NC)"

release-build: ## Build release packages
	@echo "$(GREEN)Building release packages...$(NC)"
	$(MAKE) clean-build
	$(MAKE) build-native
	$(MAKE) build-python
	@echo "$(GREEN)Release packages built!$(NC)"

release-upload: ## Upload to PyPI
	@echo "$(GREEN)Uploading to PyPI...$(NC)"
	twine upload $(DIST_DIR)/*
	@echo "$(GREEN)Release uploaded to PyPI!$(NC)"

release-tag: ## Create git tag for release
	@echo "$(GREEN)Creating git tag for version $(VERSION)...$(NC)"
	git tag -a v$(VERSION) -m "Release version $(VERSION)"
	git push origin v$(VERSION)
	@echo "$(GREEN)Git tag created and pushed!$(NC)"

# Maintenance targets
.PHONY: clean clean-all update-deps security-audit
clean: clean-build ## Clean build artifacts and cache
	@echo "$(GREEN)Cleaning cache and temporary files...$(NC)"
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .hypothesis -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.log" -delete
	find . -type f -name "*.tmp" -delete
	@echo "$(GREEN)Cleanup completed!$(NC)"

clean-all: clean docker-clean ## Clean everything including Docker
	@echo "$(GREEN)Deep cleaning completed!$(NC)"

update-deps: ## Update dependencies
	@echo "$(GREEN)Updating dependencies...$(NC)"
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install --upgrade -r requirements.txt
	$(PIP) install --upgrade -r requirements-dev.txt
	@if [ -d "$(RUST_DIR)" ]; then cd $(RUST_DIR) && $(CARGO) update; fi
	@echo "$(GREEN)Dependencies updated!$(NC)"

security-audit: ## Run security audit
	@echo "$(GREEN)Running security audit...$(NC)"
	$(PIP) audit
	@if [ -d "$(RUST_DIR)" ]; then cd $(RUST_DIR) && $(CARGO) audit; fi
	@echo "$(GREEN)Security audit completed!$(NC)"

# Platform-specific targets
.PHONY: install-windows install-macos install-linux
install-windows: ## Install Windows-specific dependencies
	@echo "$(GREEN)Installing Windows-specific dependencies...$(NC)"
	$(PIP) install pywin32 wmi
	@echo "$(GREEN)Windows dependencies installed!$(NC)"

install-macos: ## Install macOS-specific dependencies
	@echo "$(GREEN)Installing macOS-specific dependencies...$(NC)"
	$(PIP) install pyobjc-framework-Network
	@echo "$(GREEN)macOS dependencies installed!$(NC)"

install-linux: ## Install Linux-specific dependencies
	@echo "$(GREEN)Installing Linux-specific dependencies...$(NC)"
	$(PIP) install python-prctl
	@echo "$(GREEN)Linux dependencies installed!$(NC)"

# Utility targets
.PHONY: version info requirements
version: ## Show version information
	@echo "$(CYAN)NetStress Version: $(VERSION)$(NC)"
	@echo "$(CYAN)Platform: $(PLATFORM)$(NC)"
	@echo "$(CYAN)Architecture: $(UNAME_M)$(NC)"
	@$(PYTHON) --version
	@$(CARGO) --version 2>/dev/null || echo "Cargo not available"

info: ## Show project information
	@echo "$(CYAN)NetStress - Military-Grade Network Testing Framework$(NC)"
	@echo "$(YELLOW)Version: $(VERSION)$(NC)"
	@echo "$(YELLOW)Platform: $(PLATFORM) ($(UNAME_M))$(NC)"
	@echo "$(YELLOW)Python: $(shell $(PYTHON) --version)$(NC)"
	@echo "$(YELLOW)Rust: $(shell $(CARGO) --version 2>/dev/null || echo 'Not available')$(NC)"
	@echo ""
	@echo "$(GREEN)Project Structure:$(NC)"
	@echo "  $(SRC_DIR)/          - Python source code"
	@echo "  $(NATIVE_DIR)/       - Native components (Rust/C)"
	@echo "  $(TESTS_DIR)/        - Test suite"
	@echo "  $(DOCS_DIR)/         - Documentation"
	@echo "  benchmarks/    - Performance benchmarks"
	@echo ""
	@echo "$(GREEN)Key Features:$(NC)"
	@echo "  ✓ Cross-platform support (Windows/macOS/Linux)"
	@echo "  ✓ Adaptive hardware detection"
	@echo "  ✓ Zero-copy networking backends"
	@echo "  ✓ Military-grade evasion techniques"
	@echo "  ✓ Property-based testing"

requirements: ## Generate requirements.txt from pyproject.toml
	@echo "$(GREEN)Generating requirements.txt...$(NC)"
	$(PIP) install pip-tools
	pip-compile pyproject.toml
	@echo "$(GREEN)Requirements generated!$(NC)"

# CI/CD targets
.PHONY: ci-test ci-build ci-deploy
ci-test: ## Run CI test suite
	@echo "$(GREEN)Running CI test suite...$(NC)"
	$(MAKE) check-all
	$(MAKE) test
	$(MAKE) test-security
	@echo "$(GREEN)CI tests completed!$(NC)"

ci-build: ## Build for CI/CD
	@echo "$(GREEN)Building for CI/CD...$(NC)"
	$(MAKE) build-native
	$(MAKE) build-python
	@echo "$(GREEN)CI build completed!$(NC)"

ci-deploy: ## Deploy from CI/CD
	@echo "$(GREEN)Deploying from CI/CD...$(NC)"
	$(MAKE) release-upload
	$(MAKE) docker-push
	@echo "$(GREEN)CI deployment completed!$(NC)"

# Special targets
.PHONY: benchmark-all stress-test
benchmark-all: ## Run comprehensive benchmarks
	@echo "$(GREEN)Running comprehensive benchmarks...$(NC)"
	$(PYTHON) benchmarks/run_benchmarks.py --comprehensive
	$(PYTHON) benchmarks/cross_platform_benchmark.py
	$(PYTHON) benchmarks/regression_test.py
	@echo "$(GREEN)Comprehensive benchmarks completed!$(NC)"

stress-test: ## Run stress tests
	@echo "$(GREEN)Running stress tests...$(NC)"
	$(PYTHON) -m pytest $(TESTS_DIR)/test_stress_*.py -v --tb=short
	@echo "$(GREEN)Stress tests completed!$(NC)"

# Make sure intermediate files are not deleted
.PRECIOUS: %.o %.so %.dylib %.dll

# Phony targets (targets that don't create files)
.PHONY: help install install-dev install-native install-deps build build-native build-rust build-c build-python clean-build test test-unit test-integration test-properties test-cross-platform test-performance test-security test-coverage lint format check-format check-types check-security check-all docs docs-build docs-serve docs-clean dev-setup dev-run dev-test dev-benchmark dev-profile docker-build docker-run docker-test docker-push docker-clean release release-check release-build release-upload release-tag clean clean-all update-deps security-audit install-windows install-macos install-linux version info requirements ci-test ci-build ci-deploy benchmark-all stress-test