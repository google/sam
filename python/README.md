# SAM Python Client (Preview)

This package provides Python artifacts for the SAM sovereign auth flow:

- Protocol IDs: `/sam/auth/1.0.0`, `/sam/a2a/1.0.0`, `/sam/mcp/1.0.0`
- Passport biscuit validation (Hub-signed Ed25519 envelope)
- Application-layer auth handshake helpers
- Local reputation trust cache backed by SQLite

## Install

```bash
cd python
python -m pip install -e .
```

## Notes

- Transport compliance (TLS 1.3-only, QUIC first, TCP+TLS fallback) must be
  configured in the py-libp2p host builder for your runtime.
- This library focuses on identity/auth hook and trust cache parity with Go.
- Default relay/rendezvous host hint is `app.sam-mesh.dev`.
