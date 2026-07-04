REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin

# disable CGO by default for static binaries
CGO_ENABLED=0
export GOROOT GO111MODULE CGO_ENABLED

# Autodetect Android SDK and NDK
ANDROID_HOME_RESOLVED:=$(if $(ANDROID_HOME),$(ANDROID_HOME),$(HOME)/Android/Sdk)
ANDROID_NDK_LATEST:=$(shell ls -d $(ANDROID_HOME_RESOLVED)/ndk/* 2>/dev/null | sort -V | tail -n 1)
ANDROID_NDK_TOOLCHAIN=$(ANDROID_NDK_LATEST)/toolchains/llvm/prebuilt/linux-x86_64/bin
ANDROID_CC_ARM64=$(ANDROID_NDK_TOOLCHAIN)/aarch64-linux-android30-clang
ANDROID_CC_X86_64=$(ANDROID_NDK_TOOLCHAIN)/x86_64-linux-android30-clang

build:
	go build -v -o "$(OUT_DIR)/sam-node" ./cmd/sam-node
	go build -v -o "$(OUT_DIR)/sam-hub" ./cmd/sam-hub
	go build -v -o "$(OUT_DIR)/mcp-client" ./cmd/mcp-client

.PHONY: mobile-ffi-host mobile-ffi-android mobile-ffi-ios mobile-ffi mobile-app-apk mobile-app-apk-emulator
mobile-ffi-host:
	mkdir -p "$(OUT_DIR)"
	CGO_ENABLED=1 go build -v -buildmode=c-shared -o "$(OUT_DIR)/libsam.so" ./mobile/sam-node-ffi

mobile-ffi-android:
	@if [ -z "$(ANDROID_NDK_LATEST)" ]; then \
		echo "Error: Android NDK not found under $(ANDROID_HOME_RESOLVED)/ndk/. Please install NDK (Side-by-side) via Android Studio or sdkmanager." >&2; \
		exit 1; \
	fi
	mkdir -p "$(OUT_DIR)/android"
	GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=$(ANDROID_CC_ARM64) go build -v -buildmode=c-shared -o "$(OUT_DIR)/android/libsam.so" ./mobile/sam-node-ffi

mobile-ffi-ios:
	mkdir -p "$(OUT_DIR)/ios"
	GOOS=ios GOARCH=arm64 CGO_ENABLED=1 go build -v -buildmode=c-archive -o "$(OUT_DIR)/ios/libsam.a" ./mobile/sam-node-ffi

mobile-ffi: mobile-ffi-host mobile-ffi-android mobile-ffi-ios

mobile-app-apk: mobile-ffi-android
	mkdir -p mobile/sam-node-app/android/app/src/main/jniLibs/arm64-v8a
	cp "$(OUT_DIR)/android/libsam.so" mobile/sam-node-app/android/app/src/main/jniLibs/arm64-v8a/libsam.so
	cd mobile/sam-node-app && flutter build apk --release

mobile-app-apk-emulator:
	@if [ -z "$(ANDROID_NDK_LATEST)" ]; then \
		echo "Error: Android NDK not found under $(ANDROID_HOME_RESOLVED)/ndk/. Please install NDK (Side-by-side) via Android Studio or sdkmanager." >&2; \
		exit 1; \
	fi
	mkdir -p "$(OUT_DIR)/android-x86_64"
	GOOS=android GOARCH=amd64 CGO_ENABLED=1 CC=$(ANDROID_CC_X86_64) go build -v -buildmode=c-shared -o "$(OUT_DIR)/android-x86_64/libsam.so" ./mobile/sam-node-ffi
	mkdir -p mobile/sam-node-app/android/app/src/main/jniLibs/x86_64
	cp "$(OUT_DIR)/android-x86_64/libsam.so" mobile/sam-node-app/android/app/src/main/jniLibs/x86_64/libsam.so
	cd mobile/sam-node-app && flutter build apk --release

.PHONY: proto
proto:
	./hack/gen-proto.sh

clean:
	rm -rf "$(OUT_DIR)/"

.PHONY: kind-up kind-logs kind-down
kind-up:
	./development/kind/run.sh $(ARGS)

kind-logs:
	./development/kind/run.sh -l

kind-down:
	kind delete cluster --name sam-kind

.PHONY: kind-local-node
kind-local-node:
	./development/kind/run-local-node.sh $(ARGS)

.PHONY: kind-e2e-mesh
kind-e2e-mesh: build
	./development/kind/test-mesh-e2e.sh

test:
	CGO_ENABLED=1 go test -v -race -count 1 $(if $(WHAT),-run $(WHAT)) ./...

.PHONY: test-python test-python-e2e
test-python:
	python3 -m venv sam-mcp-python/.venv
	./sam-mcp-python/.venv/bin/pip install -e ./sam-mcp-python[test]
	./sam-mcp-python/.venv/bin/pytest sam-mcp-python/tests/unit

test-python-e2e: build docker-build
	bats --verbose-run tests/e2e/python_sdk_test.bats

e2e-test: build docker-build
	bats --verbose-run $(if $(WHAT),--filter "$(WHAT)") tests/e2e/

test-e2e: build docker-build
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

# code formatters
.PHONY: fmt
fmt:
	go fmt ./...

# code linters
lint: fmt
	hack/lint.sh

.PHONY: verify
verify:
	./hack/verify-generated.sh

update:
	go mod tidy

docker-build-hub:
	docker build --load -t sam-hub:local -f Dockerfile.sam-hub .

docker-build-node:
	docker build --load --no-cache -t sam-node:local -f Dockerfile.sam-node .

docker-build-mock-oidc:
	docker build --load -t sam-mock-oidc:local -f tests/e2e/docker/Dockerfile.mock-oidc .

docker-build-e2e-runtime:
	docker build --load -t sam-e2e-runtime:local -f tests/e2e/docker/Dockerfile.sam-runtime .

docker-build: docker-build-hub docker-build-node docker-build-mock-oidc docker-build-e2e-runtime

.PHONY: docker-build-hub docker-build-node docker-build-mock-oidc docker-build-e2e-runtime docker-build
