# Makefile for go-authx
# IMPORTANT: This file uses TAB characters for indentation, not spaces!

.PHONY: all test tests test-ci test-cover test-race cover coverage coverage-ci fmt fmt-fix lint gosec govulncheck vet deps tidy clean help

# ========================================
# Variables
# ========================================
BUILD_DIR=build

GOTESTFLAGS ?= -count=1 -timeout=2m
RACE_TESTFLAGS ?= -count=1 -timeout=3m
UNIT_PKGS ?= ./httpclient/... ./grpcclient/... ./grpcserver/... ./oauth2client/...
UNIT_SHUFFLE ?= on
RACE_SHUFFLE ?= on
COVER_SHUFFLE ?= off
JUNIT_FILE ?=
COVERAGE_MIN ?= 80
COVERMODE ?= atomic
COVERPROFILE ?= $(BUILD_DIR)/coverage.out

FMT_FIND := find . -type f -name '*.go' -not -path './build/*'

# Auto-add GOPATH/bin to PATH
GOBIN := $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

# ========================================
# Default target
# ========================================
all: test


# ========================================
# Run tests
# ========================================
test:
	@echo "Running tests..."
	go test $(GOTESTFLAGS) -shuffle=$(UNIT_SHUFFLE) ./...

# Deterministic list of packages used in CI; keeps tests/coverage aligned
test-ci:
	@echo "Running CI unit tests (packages: $(UNIT_PKGS))..."
	@echo "Shuffle: $(UNIT_SHUFFLE)"
	@if [ -n "$(JUNIT_FILE)" ] && command -v gotestsum >/dev/null; then \
		mkdir -p $(dir $(JUNIT_FILE)); \
		gotestsum --junitfile $(JUNIT_FILE) --format testname -- \
			$(GOTESTFLAGS) -shuffle=$(UNIT_SHUFFLE) $(UNIT_PKGS); \
	else \
		go test $(GOTESTFLAGS) -shuffle=$(UNIT_SHUFFLE) $(UNIT_PKGS); \
	fi

# Alias for convenience (e.g., `make tests`)
tests: test

# Run tests with coverage reporting
test-cover:
	@$(MAKE) coverage

# Run tests with the race detector enabled
test-race:
	@echo "Running tests with race detector..."
	go test $(RACE_TESTFLAGS) -race -shuffle=$(RACE_SHUFFLE) $(UNIT_PKGS)

cover:
	@$(MAKE) coverage-ci

gosec:
	@echo "Running gosec..."
	@if [ -f tools/ci/.gosec.json ]; then \
		gosec -exclude-generated -conf tools/ci/.gosec.json ./...; \
	else \
		gosec -exclude-generated ./...; \
	fi

govulncheck:
	@echo "Running govulncheck..."
	govulncheck ./...

coverage-ci:
	@echo "Generating deterministic coverage profile..."
	@mkdir -p $(BUILD_DIR)
	go test $(GOTESTFLAGS) -shuffle=$(COVER_SHUFFLE) -covermode=$(COVERMODE) -coverprofile=$(COVERPROFILE) $(UNIT_PKGS)
	@go tool cover -func=$(COVERPROFILE) | tail -n 1

coverage:
	@$(MAKE) coverage-ci


# ========================================
# Format code
# ========================================
fmt: fmt-fix

fmt-fix:
	@echo "Running gofumpt..."
	@$(FMT_FIND) -print0 | xargs -0 gofumpt -w
	@echo "Running gofmt -s..."
	@$(FMT_FIND) -print0 | xargs -0 gofmt -s -w
	@echo "Running goimports..."
	@$(FMT_FIND) -print0 | xargs -0 goimports -w
	@echo "Formatting complete"

# ========================================
# Lint code
# ========================================
lint:
	@echo "Running linters..."
	golangci-lint run ./...

vet:
	@echo "Running go vet..."
	go vet ./...

# ========================================
# Dependencies
# ========================================
deps:
	@echo "Downloading dependencies..."
	go mod download
	@echo "Dependencies downloaded"

tidy:
	@echo "Tidying dependencies..."
	go mod tidy
	@echo "Dependencies tidied"

# ========================================
# Clean
# ========================================
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

# ========================================
# Help
# ========================================
help:
	@echo "Available targets:"
	@echo "  make all           - Run tests (default)"
	@echo "  make test          - Run all tests"
	@echo "  make tests         - Alias for 'make test'"
	@echo "  make test-ci       - Run tests for CI (deterministic)"
	@echo "  make test-cover    - Run tests with coverage reporting"
	@echo "  make test-race     - Run tests with the race detector"
	@echo "  make cover         - Generate coverage profile"
	@echo "  make coverage      - Alias for 'make cover'"
	@echo "  make fmt           - Format code with gofumpt/gofmt/goimports"
	@echo "  make lint          - Run golangci-lint"
	@echo "  make vet           - Run go vet"
	@echo "  make gosec         - Run gosec security scanner"
	@echo "  make govulncheck   - Run govulncheck vulnerability scanner"
	@echo "  make deps          - Download dependencies"
	@echo "  make tidy          - Tidy go.mod and go.sum"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make help          - Show this help message"
