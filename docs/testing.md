# Testing Guide: Validating SAM

SAM has comprehensive test coverage across three levels:

1. **Unit Tests** (Go): Pure function testing
2. **Integration Tests** (Go): Multi-node scenarios with namespaces
3. **E2E Tests** (BATS): CLI validation and user workflows

---

## Test Architecture

### Test Isolation

Tests use **Linux user namespaces** to isolate network state:

```go
func TestA2ACall(t *testing.T) {
    // Each test runs in CLONE_NEWNET namespace
    // Network stack is isolated
    // DHT doesn't interfere with other tests
    testutils.Run(t, f, testutils.CLONE_NEWNET)
}
```

**Benefits:**

- No test pollution (each test has clean network)
- Can run tests in parallel
- Can simulate network conditions (no connectivity, firewall)
- Each test cleanup is automatic

### Test Levels

```
┌──────────────────────────────────────────┐
│  E2E Tests (BATS)                        │
│  - CLI commands                          │
│  - User workflows                        │
│  - Dry-run and inspect                   │
└──────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────┐
│  Integration Tests (Go)                  │
│  - Multi-node scenarios                  │
│  - DHT discovery                         │
│  - A2A calls                             │
│  - Federation isolation                  │
└──────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────┐
│  Unit Tests (Go)                         │
│  - Biscuit parsing                       │
│  - Vouch verification                    │
│  - Card encoding/decoding                │
└──────────────────────────────────────────┘
```

---

## Unit Tests

Unit tests validate individual components in isolation.

### Running Unit Tests

```bash
# Run all unit tests
go test ./...

# Run with race detection
go test -race ./...

# Run specific package
go test ./pkg/economy

# Run specific test
go test -run TestParseBiscuit ./pkg/economy

# Show coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Key Test Files

| Package | Tests | Purpose |
|---------|-------|---------|
| `pkg/economy` | `TestParseBiscuit`, `TestCheckSkill` | Biscuit token parsing and skill verification |
| `pkg/protocol` | `TestAgentCard`, `TestDiscovery` | Agent card encoding/decoding, peer discovery |
| `pkg/net` | `TestNodeStart`, `TestDHT` | Node lifecycle, DHT initialization |
| `pkg/identity` | `TestVouchVerify`, `TestVouchExpiry` | Vouch signature and expiry checks |

### Example Unit Test

```go
func TestParseBiscuit(t *testing.T) {
    parser := economy.SimpleBiscuitParser{}
    
    // Test simple biscuit
    ctx := context.Background()
    parsed, err := parser.Parse(ctx, "alice;allow_skill=weather-bot")
    
    if err != nil {
        t.Fatalf("Parse failed: %v", err)
    }
    if parsed.Subject != "alice" {
        t.Errorf("Expected subject 'alice', got %q", parsed.Subject)
    }
    if len(parsed.AllowedSkills) != 1 {
        t.Errorf("Expected 1 skill, got %d", len(parsed.AllowedSkills))
    }
    if parsed.AllowedSkills[0] != "weather-bot" {
        t.Errorf("Expected 'weather-bot', got %q", parsed.AllowedSkills[0])
    }
}
```

---

## Integration Tests

Integration tests validate multi-node scenarios with network isolation.

### Running Integration Tests

```bash
# Run all integration tests
go test -race -count=1 ./tests/integration

# Run specific test
go test -race -count=1 -run TestCUJ1 ./tests/integration

# Verbose output
go test -race -count=1 -v ./tests/integration

# Timeout (integration tests can take 30-60s)
go test -race -timeout=5m -count=1 ./tests/integration
```

### Key Integration Tests

| Test | Time | Purpose |
|------|------|---------|
| `TestCUJ1Stealth` | 45s | Federation DHT isolation (dark mesh) |
| `TestCUJ2HolePunch` | 60s | Relay-assisted connectivity (DCUtR) |
| `TestA2ACall` | 30s | Agent-to-agent RPC with Biscuit auth |
| `TestMeshDHT` | 40s | Multi-federation discovery |

### Example Integration Test

```go
func TestCUJ1StealthAudit(t *testing.T) {
    // Run in isolated network namespace
    testutils.Run(t, func(f *testutils.Framework) {
        // Create two federations: alpha, beta
        alphaA, _ := cujStartNode(t, f, "alpha", "alpha-a")
        alphaB, _ := cujStartNode(t, f, "alpha", "alpha-b")
        betaA, _ := cujStartNode(t, f, "beta", "beta-a")

        // Wait for DHT convergence
        cujWaitDiscover(t, alphaA, alphaB.PeerID(), 10*time.Second)
        
        // Alpha agents should discover each other
        _, err := alphaA.Discover(alphaB.PeerID())
        if err != nil {
            t.Fatalf("alphaA should discover alphaB: %v", err)
        }

        // But Beta agent should NOT discover Alpha agents
        // (federation isolation enforced at DHT level)
        _, err = betaA.Discover(alphaA.PeerID())
        if err == nil {
            t.Fatalf("betaA should NOT discover alphaA (federation isolation)")
        }
    }, testutils.CLONE_NEWNET)
}
```

### Test Framework Helpers

The `testutils` package provides helpers for integration tests:

```go
// Start a node in a federation
node, _ := cujStartNode(t, f, federationID, nodeName)

// Wait for node to discover a peer
cujWaitDiscover(t, node, targetPeerID, timeout)

// Get relay circuit address for NAT traversal
circuit := cujRelayCircuitAddr(t, f, relayNode, targetNode)

// Wait for direct connection (DCUtR holepunch)
cujWaitForDirectConn(t, node1, node2, timeout)

// Bootstrap addresses
addrs := cujBootstrapAddrs(f, bootstrapNode)
```

---

## E2E Tests (BATS)

E2E tests use BATS (Bash Automated Testing System) to validate CLI commands.

### Running E2E Tests

```bash
# Build binary first
make build

# Run all E2E tests
make test-e2e

# Run with verbose output
SAM_BINARY=./bin/sam bats --verbose-run tests/e2e/sam.bats

# Run specific test
SAM_BINARY=./bin/sam bats --filter "sam inspect" tests/e2e/sam.bats
```

### Key E2E Tests

| Test | Purpose |
|------|---------|
| `sam up --help` | Verify help output |
| `sam publish --help` | Verify publish command |
| `sam inspect biscuit` | Parse and explain Biscuit token |
| `sam publish --dry-run=client` | Build card without network |
| `sam call --dry-run=client` | Validate call without network |
| `sam inspect card` | Decode Agent Card JSON |

### Example BATS Test

```bash
@test "sam inspect biscuit parses and explains a token" {
    token="alice;allow_skill=risk-audit,weather-bot"
    run "$SAM_BINARY" inspect biscuit "$token"
    
    # Assertion: command succeeded
    [[ "$status" -eq 0 ]]
    
    # Assertion: output contains subject
    [[ "$output" == *"alice"* ]]
    
    # Assertion: output contains skills
    [[ "$output" == *"risk-audit"* ]]
    [[ "$output" == *"weather-bot"* ]]
}
```

### BATS Syntax

```bash
# Run command (output in $output, exit code in $status)
run "$SAM_BINARY" command arg1 arg2

# Assertions
[[ "$status" -eq 0 ]]              # Exit code is 0 (success)
[[ "$output" == *"text"* ]]        # Output contains text
[[ "$output" =~ ^regex$ ]]         # Output matches regex
[[ ! "$output" =~ pattern ]]       # Output does NOT match pattern
```

---

## Running Full Test Suite

### Quick Test Run

```bash
# Unit tests only (fast, ~10s)
go test ./...

# With race detection
go test -race ./...
```

### Full Suite

```bash
# Everything: unit + integration + E2E
make test

# What make test does:
# 1. go test -race -count=1 ./...           (unit + integration, ~60s)
# 2. make build                             (compile binary)
# 3. bats tests/e2e/sam.bats                (E2E tests, ~30s)
```

### Expected Output

```
go test -race -count=1 ./...
ok  	sam	89.234s    (82 tests passed)

make build
go build -v -o ./bin/sam ./cmd/sam

SAM_BINARY=./bin/sam bats --verbose-run tests/e2e/sam.bats
 ✓ sam up --help returns success
 ✓ sam publish --help returns success
 ✓ sam inspect biscuit parses token
 ...
12 tests, 0 failures
```

---

## Contributing: Test Requirements

When submitting a PR, ensure:

1. **All unit tests pass**
   ```bash
   go test -race ./...
   ```

2. **No race conditions**
   ```bash
   go test -race ./...
   ```

3. **All integration tests pass**
   ```bash
   go test -race -count=1 ./tests/integration
   ```

4. **All E2E tests pass**
   ```bash
   make test-e2e
   ```

5. **New features have tests**
   - Add unit test in same package
   - Add integration test if multi-node
   - Add BATS test if CLI-facing

### Test Checklist

```bash
# Before submitting PR
make test                    # Full suite
go test -race ./...         # Explicit race check
go test -cover ./...        # Check coverage
```

---

## Performance Testing

### Benchmarking

```bash
# Run benchmarks
go test -bench=. ./pkg/economy

# Benchmark with memory stats
go test -bench=. -benchmem ./pkg/economy

# CPU profile
go test -bench=. -cpuprofile=cpu.prof ./pkg/economy
go tool pprof cpu.prof

# Memory profile
go test -bench=. -memprofile=mem.prof ./pkg/economy
go tool pprof mem.prof
```

### Example Benchmark

```go
func BenchmarkParseBiscuit(b *testing.B) {
    parser := economy.SimpleBiscuitParser{}
    ctx := context.Background()
    token := "alice;allow_skill=weather-bot,risk-audit"
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = parser.Parse(ctx, token)
    }
}
```

---

## Debugging Tests

### Verbose Output

```bash
# See all log output
go test -v ./tests/integration

# With debug flag
SAM_DEBUG=1 go test -v ./...
```

### GDB Debugging

```bash
# Run test with GDB
dlv test ./pkg/protocol -- -test.run TestAgentCard
```

### Print Debugging

```go
import "fmt"

func TestExample(t *testing.T) {
    fmt.Printf("Debug: value=%v\n", someValue)
}
```

---

## Next Steps

- **[Quick Start](#/guides/dark-mesh.md)**: Set up SAM locally
- **[CLI Reference](#/cli/reference.md)**: Test with real commands
- **[Contributing](#/contributing.md)**: Submit a test PR
