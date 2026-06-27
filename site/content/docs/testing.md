# Testing

Current testing is intentionally minimal and aligned with the current binaries.

## Test Layers

1. Go tests: `make test`
2. BATS CLI tests: `make test-e2e`
3. Containerized BATS mesh tests: `make test-e2e-container`

## Commands

```bash
make build
make test
make test-e2e
make test-e2e-container
```

## Go Tests

Run all Go tests with race detection:

```bash
make test
```

Run only integration package:

```bash
go test ./tests/integration/...
```

## BATS CLI Tests

These tests validate current command behavior for:

- `sam-node`
- `sam-hub`

Run:

```bash
make test-e2e
```

## Containerized Mesh BATS

The container framework is implemented in:

- `tests/e2e/lib/container_mesh.bash`

It starts:

1. mock OIDC container
2. `sam-hub` container
3. multiple `sam-node` containers

Run:

```bash
make test-e2e-container
```

Optional image override:

```bash
MESH_RUNTIME_IMAGE=sam-e2e-runtime:dev make test-e2e-container
```

## Troubleshooting

- Ensure Docker daemon is running before container tests.
- Ensure `bats` is installed and available in `PATH`.
- If a test fails, inspect containers:

```bash
docker ps -a
docker logs <container-name>
```
