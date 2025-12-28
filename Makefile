.PHONY: all build clean mpcd lux-mpc-cli test test-verbose test-coverage e2e-test e2e-clean cleanup-test-env test-all clean-all up down logs

# Go 1.26 experimental features:
#   runtimesecret - zeroes stack/register state after secret.Do() for forward secrecy
#   simd          - SIMD intrinsics (amd64/arm64)
GOEXPERIMENT ?= runtimesecret,simd

all: build

build: mpcd lux-mpc-cli

mpcd:
	GOWORK=off GOEXPERIMENT=$(GOEXPERIMENT) go build -o mpcd ./cmd/mpcd

lux-mpc-cli:
	GOWORK=off GOEXPERIMENT=$(GOEXPERIMENT) go build -o lux-mpc-cli ./cmd/lux-mpc-cli

# Run all tests (json1 enables SQLite JSON functions for ORM JSONB queries)
test:
	CGO_ENABLED=1 GOEXPERIMENT=$(GOEXPERIMENT) go test -tags json1 ./...

test-verbose:
	CGO_ENABLED=1 GOEXPERIMENT=$(GOEXPERIMENT) go test -tags json1 -v ./...

test-coverage:
	CGO_ENABLED=1 GOEXPERIMENT=$(GOEXPERIMENT) go test -tags json1 -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# E2E
e2e-test: build
	@echo "Running E2E integration tests..."
	cd e2e && make test

e2e-test-coverage: build
	@echo "Running E2E integration tests with coverage..."
	cd e2e && make test-coverage

e2e-clean:
	@echo "Cleaning up E2E test artifacts..."
	cd e2e && make clean

cleanup-test-env:
	@echo "Performing comprehensive test environment cleanup..."
	cd e2e && ./cleanup_test_env.sh

test-all: test e2e-test

# Local dev environment (compose.yml)
up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

# Clean
clean:
	rm -f mpcd lux-mpc-cli
	rm -f coverage.out coverage.html

clean-all: clean e2e-clean
