.PHONY: build test worker audit clean tidy

# Default: regex scanner, real Sibyl. Set TAGS to override.
TAGS ?=
FIXTURES ?= ../sibyl-sentry-fixtures
TEMPORAL ?= localhost:7233

build:
	go build -tags "$(TAGS)" ./...

# Run all tests; fixture-dependent tests skip if fixtures aren't found.
test:
	SENTRY_FIXTURES_PATH=$(abspath $(FIXTURES)) go test -tags "$(TAGS)" -count=1 ./...

# Run the worker (assumes Temporal dev server already running on localhost:7233).
worker:
	go run -tags "$(TAGS)" ./cmd/sentry-worker \
		-temporal $(TEMPORAL) \
		-owners $(FIXTURES)/config/owners.json

# Submit an audit. Pass TARGET=path to override.
TARGET ?= $(FIXTURES)
audit:
	go run -tags "$(TAGS)" ./cmd/sentry-audit \
		-temporal $(TEMPORAL) \
		-target $(TARGET)

# Stub-mode build for scaffold verification (no real Sibyl needed).
build-stub:
	go build -tags "sibyl_stub $(TAGS)" ./...

test-stub:
	SENTRY_FIXTURES_PATH=$(abspath $(FIXTURES)) go test -tags "sibyl_stub $(TAGS)" -count=1 ./...

# YARA build (requires libyara installed).
build-yara:
	go build -tags "yara $(TAGS)" ./...

tidy:
	go mod tidy

clean:
	go clean ./...
