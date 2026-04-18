# Contributing to SAM

We welcome contributions! This guide covers:

1. **Development Setup**: Get SAM building locally
2. **Code Style**: Follow SAM conventions
3. **Testing**: Ensure quality with full test coverage
4. **Submitting Changes**: PR workflow

---

## Development Setup

### Prerequisites

- **Go 1.21+**: https://golang.org/doc/install
- **Make**: `sudo apt-get install make` (Linux) or `brew install make` (macOS)
- **BATS**: `sudo apt-get install bats` (Linux) or `brew install bats-core` (macOS)
- **Git**: For version control

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/your-org/sam.git
cd sam

# Build the binary
make build

# Verify build
./bin/sam --help
```

### Environment Setup

```bash
# Set GOPATH (if not already set)
export GOPATH=$HOME/go

# Add to PATH
export PATH=$PATH:$GOPATH/bin

# Run tests
make test
```

---

## Code Style

### Go Conventions

SAM follows standard Go conventions:

1. **Formatting**: Use `gofmt`
   ```bash
   gofmt -s -w cmd/sam/main.go
   ```

2. **Linting**: Use `golangci-lint`
   ```bash
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   golangci-lint run ./...
   ```

3. **Naming**
   - Package names: lowercase, no underscores (`samnet`, not `sam_net`)
   - Function names: `CamelCase` (exported) or `camelCase` (private)
   - Constants: `UPPER_CASE` (exported) or `upper_case` (private)
   - Interfaces: `Reader`, `Writer`, `Closer` (noun + verb pattern)

4. **Comments**
   ```go
   // Package net provides libp2p networking for SAM agents.
   package net

   // Node represents a libp2p host with DHT routing.
   type Node interface {
       // Start begins listening and DHT discovery.
       Start(ctx context.Context) error
   }
   ```

5. **Error Handling**
   ```go
   // Good
   if err != nil {
       return fmt.Errorf("loading vouch: %w", err)
   }

   // Bad
   if err != nil {
       panic(err)  // Don't panic in libraries
   }
   ```

### File Organization

```
sam/
├── cmd/sam/                    # CLI commands
│   ├── main.go                # Entry point
│   ├── root.go                # Root command
│   ├── publish.go             # Publish command
│   ├── call.go                # Call command
│   └── ...
├── pkg/                        # Libraries (exported)
│   ├── net/                   # Networking
│   │   ├── node.go
│   │   ├── options.go
│   │   └── node_test.go
│   ├── protocol/              # Protocols
│   │   ├── a2a.go
│   │   ├── agent_card.go
│   │   └── a2a_test.go
│   ├── economy/               # Credentials and payments
│   │   ├── biscuit.go
│   │   ├── middleware.go
│   │   └── biscuit_test.go
│   └── identity/              # Identity and authentication
│       ├── vouch.go
│       ├── device_flow.go
│       └── vouch_test.go
├── internal/                   # Internal packages (not exported)
│   ├── db/                    # Database abstractions
│   │   ├── manager.go
│   │   ├── store.go
│   │   └── codec.go
│   └── testutils/             # Testing helpers
│       └── userns.go
├── tests/                      # Test suites
│   ├── integration/           # Go integration tests
│   │   ├── a2a_test.go
│   │   ├── cuj_test.go
│   │   └── mesh_test.go
│   └── e2e/                   # BATS E2E tests
│       └── sam.bats
└── docs/                       # Documentation
    ├── README.md
    ├── guides/
    ├── cli/
    └── concepts/
```

---

## Testing

### Test Coverage Requirements

All contributions must include tests:

1. **Unit tests** for new functions
2. **Integration tests** for multi-node scenarios
3. **E2E tests** for CLI changes

### Running Tests

```bash
# All tests
make test

# Unit + Integration only
go test -race -count=1 ./...

# E2E only
make build
make test-e2e

# Specific test
go test -run TestFunctionName ./pkg/package

# With coverage
go test -cover ./...
```

### Writing Unit Tests

```go
func TestNewBiscuit(t *testing.T) {
    // Arrange
    parser := economy.SimpleBiscuitParser{}
    token := "alice;allow_skill=weather"

    // Act
    parsed, err := parser.Parse(context.Background(), token)

    // Assert
    if err != nil {
        t.Fatalf("Parse failed: %v", err)
    }
    if parsed.Subject != "alice" {
        t.Errorf("Expected 'alice', got %q", parsed.Subject)
    }
}
```

### Writing Integration Tests

```go
func TestA2ACallWithBiscuit(t *testing.T) {
    testutils.Run(t, func(f *testutils.Framework) {
        // Setup
        nodea, _ := f.StartNode("federation-a")
        nodeb, _ := f.StartNode("federation-a")

        // Execute
        token := "alice;allow_skill=test-skill"
        resp, err := protocol.Execute(
            context.Background(),
            nodea.Host(),
            protocol.ExecuteRequest{
                Target: nodeb.PeerID(),
                Capability: "test-skill",
                Biscuit: token,
                MCPRequest: []byte(`{"method": "test"}`),
            },
        )

        // Assert
        if err != nil {
            t.Fatalf("Execute failed: %v", err)
        }
        if resp == nil {
            t.Errorf("Expected response")
        }
    }, testutils.CLONE_NEWNET)
}
```

### Writing BATS Tests

```bash
@test "sam publish with dry-run outputs card" {
    run "$SAM_BINARY" publish \
        --skill test-skill \
        --mcp-port 9999 \
        --dry-run=client

    [[ "$status" -eq 0 ]]
    [[ "$output" == *'"peer_id"'* ]]
    [[ "$output" == *'test-skill'* ]]
}
```

### Race Detection

Always test with race detection:

```bash
go test -race ./...
```

This catches data races that are hard to spot manually.

---

## Submitting Changes

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/issue-123
```

### 2. Make Changes

```bash
# Edit files
vim pkg/net/node.go

# Run tests frequently
go test -race ./pkg/net
```

### 3. Commit with Good Messages

```bash
git add -A
git commit -m "Add federation isolation to DHT discovery

- Scopes DHT announcements to /sam/fed/<id> namespace
- Prevents cross-federation peer discovery
- Matches federation DHT protocol prefix

Fixes #123"
```

**Commit message format:**
```
<type>: <description>

<body explaining why>

Fixes #<issue-number>
```

**Types:** `feat`, `fix`, `refactor`, `test`, `docs`, `chore`

### 4. Keep Branch Up to Date

```bash
git fetch origin
git rebase origin/main
```

### 5. Push and Create PR

```bash
git push origin feature/my-feature
```

Then create a PR on GitHub with:
- **Title**: Brief summary
- **Description**: What changed and why
- **Tests**: Mention test coverage
- **Fixes**: Reference any related issues (#123)

### 6. Code Review

- Address reviewer feedback
- Push additional commits (don't force-push)
- Reviewer will merge when approved

---

## Common Development Tasks

### Adding a New CLI Command

1. **Create command file** (`cmd/sam/mycommand.go`):
   ```go
   func newMyCmd(cfg *runConfig) *cobra.Command {
       cmd := &cobra.Command{
           Use: "mycommand",
           Short: "Do something",
           RunE: func(cmd *cobra.Command, args []string) error {
               return runMyCommand(cmd.Context(), cfg)
           },
       }
       // Add flags
       cmd.Flags().StringVar(&cfg.flag, "flag", "", "description")
       return cmd
   }

   func runMyCommand(ctx context.Context, cfg *runConfig) error {
       // Implementation
       return nil
   }
   ```

2. **Register in root** (`cmd/sam/root.go`):
   ```go
   cmd.AddCommand(newMyCmd(cfg))
   ```

3. **Add tests** (`tests/e2e/sam.bats`):
   ```bash
   @test "sam mycommand --help works" {
       run "$SAM_BINARY" mycommand --help
       [[ "$status" -eq 0 ]]
   }
   ```

### Adding a New Protocol Feature

1. **Define interface** (`pkg/protocol/myfeature.go`):
   ```go
   type MyFeature interface {
       DoSomething(ctx context.Context) error
   }
   ```

2. **Implement** (`pkg/protocol/myfeature.go`):
   ```go
   type myFeatureImpl struct {
       // fields
   }

   func (m *myFeatureImpl) DoSomething(ctx context.Context) error {
       // implementation
   }
   ```

3. **Add tests** (`pkg/protocol/myfeature_test.go`):
   ```go
   func TestMyFeature(t *testing.T) {
       // test implementation
   }
   ```

### Debugging Issues

```bash
# Verbose logging
SAM_DEBUG=1 go test -v ./...

# GDB debugging
dlv test ./pkg/net

# CPU profiling
go test -cpuprofile=cpu.prof ./...
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof ./...
go tool pprof mem.prof
```

---

## Code Review Checklist

Before submitting a PR, ensure:

- [ ] Code follows Go style guidelines
- [ ] All tests pass: `go test -race ./...`
- [ ] New code has tests
- [ ] Integration tests pass: `go test -race -count=1 ./tests/integration`
- [ ] E2E tests pass: `make test-e2e`
- [ ] Comments explain non-obvious logic
- [ ] Error messages are descriptive
- [ ] No panics in libraries (use errors)
- [ ] No TODO/FIXME comments (create issues instead)
- [ ] Documentation is updated

---

## Reporting Issues

When reporting bugs, include:

1. **Expected behavior**: What should happen?
2. **Actual behavior**: What happens instead?
3. **Steps to reproduce**: How to trigger the bug?
4. **Environment**: Go version, OS, architecture
5. **Logs**: Error messages and stack traces

### Example Issue

```
Title: sam call fails with "unknown peer" when federation is not set

Expected: sam call should use default federation
Actual: sam call fails with "unknown peer"

Steps:
1. sam publish --skill test --mcp-port 8080
2. sam call test --message "hello"

Environment:
- Go 1.21
- Ubuntu 22.04
- SAM commit abc123

Error:
  Error: discovering capability "test": no peers found for capability "test"
```

---

## Design Discussion

For significant changes, please open an issue first to discuss:

- **Architecture changes**: How will this affect the system?
- **Protocol changes**: Will this affect peer compatibility?
- **Breaking changes**: How should we handle migration?

---

## Documentation

All features should have corresponding documentation:

1. **API docs**: Godoc comments on exported types/functions
2. **User guides**: CLI examples in `/docs/guides/`
3. **Concepts**: Technical explanations in `/docs/concepts/`
4. **CLI reference**: Command documentation in `/docs/cli/`

### Godoc Example

```go
// Node represents a libp2p host with DHT routing.
// It manages connectivity, peer discovery, and protocol handlers.
type Node interface {
    // Start begins the node listening and starts DHT discovery.
    // Returns error if the node is already started.
    Start(ctx context.Context) error

    // Stop gracefully shuts down the node.
    // All streams and protocols are closed.
    Stop(ctx context.Context) error

    // Host returns the underlying libp2p host.
    Host() host.Host

    // PeerID returns the unique identifier for this node.
    PeerID() peer.ID
}
```

---

## Community

- **Issues**: Report bugs and request features
- **Discussions**: Ask questions and share ideas
- **Pull Requests**: Contribute code
- **Slack/Discord**: (if applicable)

---

## License

All contributions are licensed under the same license as SAM (typically MIT or Apache 2.0). By contributing, you agree to this.

---

## Questions?

- **Open an issue** for bug reports or features
- **Start a discussion** for design questions
- **Check the docs**: https://docs.sam.dev

Thank you for contributing! 🚀
