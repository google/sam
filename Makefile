REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin

# disable CGO by default for static binaries
CGO_ENABLED=0
export GOROOT GO111MODULE CGO_ENABLED

build:
	go build -v -o "$(OUT_DIR)/sam-node" ./cmd/sam-node
	go build -v -o "$(OUT_DIR)/sam-hub" ./cmd/sam-hub

clean:
	rm -rf "$(OUT_DIR)/"

test:
	CGO_ENABLED=1 go test -v -race -count 1 ./...

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
	SAM_BINARY=$(OUT_DIR)/sam-node bats --verbose-run tests/e2e/

# code linters
lint:
	hack/lint.sh

update:
	go mod tidy
