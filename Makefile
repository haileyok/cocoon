SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c
GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short=9 HEAD)
VERSION := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

.PHONY: help
help: ## Print info about all commands
	@echo "Commands:"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[01;32m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build all executables
	go build -ldflags "-X main.Version=$(VERSION)" -o cocoon ./cmd/cocoon

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