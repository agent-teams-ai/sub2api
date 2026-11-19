.PHONY: build generate generate-plan-catalog test test-unit test-integration test-e2e

VERSION ?= $(shell ./scripts/resolve-version.sh)
LDFLAGS ?= -s -w -X main.Version=$(VERSION)

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o bin/server ./cmd/server

generate:
	go generate ./ent
	go generate ./cmd/server

generate-plan-catalog:
	@set -eu; \
	catalog_target=../frontend/src/constants/openaiPlanTypes.builtin.json; \
	catalog_tmp=$$(mktemp "$$catalog_target.tmp.XXXXXX"); \
	trap 'rm -f "$$catalog_tmp"' EXIT HUP INT TERM; \
	go run ./cmd/generate-plan-catalog > "$catalog_tmp"; \
	chmod 0644 "$catalog_tmp"; \
	mv "$$catalog_tmp" "$$catalog_target"

test:
	go test ./...
	golangci-lint run ./...

test-unit:
	go test -tags=unit ./...

test-integration:
	go test -tags=integration ./...

test-e2e:
	./scripts/e2e-test.sh

test-e2e-local:
	go test -tags=e2e -v -timeout=300s ./internal/integration/...
