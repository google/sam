# Pinned because a stale system Go (1.24) fails to auto-resolve the
# toolchain go.mod needs; override with GOTOOLCHAIN=auto if yours does.
GOTOOLCHAIN ?= go1.25.7
export GOTOOLCHAIN

BINARY := sam-a2a-bridge

.PHONY: build test vet fmt install clean

build:
	go build -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

install:
	go install .

clean:
	rm -f $(BINARY)
