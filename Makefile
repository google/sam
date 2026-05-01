REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin

# disable CGO by default for static binaries
CGO_ENABLED=0
export GOROOT GO111MODULE CGO_ENABLED

build:
	go build -v -o "$(OUT_DIR)/sam-node" ./cmd/sam-node
	go build -v -o "$(OUT_DIR)/sam-hub" ./cmd/sam-hub
	go build -v -o "$(OUT_DIR)/mcp-client" ./cmd/mcp-client

.PHONY: proto
proto:
	./hack/gen-proto.sh

clean:
	rm -rf "$(OUT_DIR)/"

test:
	CGO_ENABLED=1 go test -v -race -count 1 ./...

.PHONY: test-python test-python-e2e
test-python:
	python3 -m venv sam-mcp-python/.venv
	./sam-mcp-python/.venv/bin/pip install -e ./sam-mcp-python[test]
	./sam-mcp-python/.venv/bin/pytest sam-mcp-python/tests/unit

test-python-e2e: build docker-build
	bats --verbose-run tests/e2e/python_sdk_test.bats

e2e-test:
	bats --verbose-run tests/e2e/

test-e2e: build
	@command -v bats >/dev/null 2>&1 || { \
		echo "bats not found; attempting install"; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y bats; \
		elif command -v brew >/dev/null 2>&1; then \
			brew install bats-core; \
		else \
			echo "Please install bats-core (https://bats-core.readthedocs.io/)"; \
			exit 1; \
		fi; \
	}
	SAM_NODE_BINARY=$(OUT_DIR)/sam-node SAM_HUB_BINARY=$(OUT_DIR)/sam-hub bats --verbose-run tests/e2e/

test-e2e-container: build docker-build
	@command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 1; }
	@docker info >/dev/null 2>&1 || { echo "docker daemon is not running"; exit 1; }
	@command -v bats >/dev/null 2>&1 || { echo "bats not found"; exit 1; }
	bats --verbose-run tests/e2e/container_mesh.bats

# code linters
lint:
	hack/lint.sh

.PHONY: verify
verify:
	./hack/verify-generated.sh

update:
	go mod tidy

docker-build-hub:
	docker build -t sam-hub:local -f Dockerfile.sam-hub .

docker-build-node:
	docker build -t sam-node:local -f Dockerfile.sam-node .

docker-build-mock-oidc:
	docker build -t sam-mock-oidc:local -f tests/e2e/docker/Dockerfile.mock-oidc .

docker-build: docker-build-hub docker-build-node docker-build-mock-oidc

.PHONY: docker-build-hub docker-build-node docker-build-mock-oidc docker-build
