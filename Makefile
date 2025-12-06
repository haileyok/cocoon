SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c
GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short=9 HEAD)
VERSION := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

# Build output directory
BUILD_DIR := dist

# Platforms to build for
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64 \
	freebsd/amd64 \
	freebsd/arm64 \
	openbsd/amd64 \
	openbsd/arm64

.PHONY: help
help: ## Print info about all commands
	@echo "Commands:"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[01;32m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build all executables
	go build -ldflags "-X main.Version=$(VERSION)" -o cocoon ./cmd/cocoon

.PHONY: build-release
build-all: ## Build binaries for all architectures
	@echo "Building for all architectures..."
	@mkdir -p $(BUILD_DIR)
	@$(foreach platform,$(PLATFORMS), \
		$(eval OS := $(word 1,$(subst /, ,$(platform)))) \
		$(eval ARCH := $(word 2,$(subst /, ,$(platform)))) \
		$(eval EXT := $(if $(filter windows,$(OS)),.exe,)) \
		$(eval OUTPUT := $(BUILD_DIR)/cocoon-$(VERSION)-$(OS)-$(ARCH)$(EXT)) \
		echo "Building $(OS)/$(ARCH)..."; \
		GOOS=$(OS) GOARCH=$(ARCH) go build -ldflags "-X main.Version=$(VERSION)" -o $(OUTPUT) ./cmd/cocoon && \
		echo "  ✓ $(OUTPUT)" || echo "  ✗ Failed: $(OS)/$(ARCH)"; \
	)
	@echo "Done! Binaries are in $(BUILD_DIR)/"

.PHONY: clean-dist
clean-dist: ## Remove all built binaries
	rm -rf $(BUILD_DIR)

.PHONY: run
run:
	go build -ldflags "-X main.Version=dev-local" -o cocoon ./cmd/cocoon && ./cocoon run

.PHONY: all
all: build

.PHONY: test
test: ## Run tests
	go clean -testcache && go test -v ./...

.PHONY: lint
lint: ## Verify code style and run static checks
	go vet ./...
	test -z $(gofmt -l ./...)

.PHONY: fmt
fmt: ## Run syntax re-formatting (modify in place)
	go fmt ./...

.PHONY: check
check: ## Compile everything, checking syntax (does not output binaries)
	go build ./...

.env:
	if [ ! -f ".env" ]; then cp example.dev.env .env; fi

.PHONY: docker-build
docker-build:
	docker build -t cocoon .
