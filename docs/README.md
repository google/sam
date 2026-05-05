# SAM Documentation

This repository currently provides a minimal SAM runtime with two binaries:

- `sam-hub`: OIDC bridge and identity biscuit issuer
- `sam-node`: mesh node CLI with login and run commands

The documentation here is intentionally small and aligned with what is implemented today.

## What Works Today

1. Build and run `sam-node` and `sam-hub`
2. Perform node login via hub OIDC flow
3. Persist identity in local node store
4. Run long-lived hub and node processes
5. Run local and containerized BATS tests
6. Expose local tools and mesh info via MCP server over HTTP SSE
7. Automated peer discovery via DHT and GossipSub events

## Start Here

- [Quick Start](quickstart.md)
- [CLI Reference](cli/reference.md)
- [Testing](testing.md)

## Notes

- Older architecture and feature-heavy docs were removed to avoid drift.
- If a feature is not documented here, assume it is not part of the current minimal scope.
