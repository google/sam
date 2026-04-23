# A2A Protocol: Agent-to-Agent Communication

## Overview

The **A2A (Agent-to-Agent)** protocol is how agents call skills offered by other agents in a federation.

- **Transport**: libp2p streams (TLS-encrypted)
- **Port/Namespace**: `/sam/a2a/1.0` 
- **Message Format**: JSON-RPC 2.0 task envelope
- **Authentication**: Vouch (federation membership)
- **Authorization**: Biscuit token (skill access)

---

## Protocol Flow

### Connection Setup

```
Client                           Server
   │                               │
   ├─ Open libp2p stream          │
   │ /sam/a2a/1.0                │
   ├─────────────────────────────>│
   │                               │
   │<───────────────────────────── │ Stream open
```

### A2A Request

```json
{
  "jsonrpc": "2.0",
  "id": "call-123",
  "method": "message",
  "params": {
    "message": "Get weather forecast for Seattle"
  },
  "headers": {
    "x-vouch": "<vouch JSON>",
    "x-biscuit": "alice;allow_skill=weather-bot",
    "x-payment": {
      "amount": 1,
      "asset": "sam-credit",
      "nonce": "1713451200000000000",
      "capability": "weather-bot"
    }
  }
}
```

### A2A Response

```json
{
  "jsonrpc": "2.0",
  "id": "call-123",
  "result": {
    "forecast": "Partly cloudy, 65°F"
  }
}
```

---

## Message Structure

### Headers

| Header | Type | Required | Purpose |
|--------|------|----------|---------|
| `x-vouch` | JSON | Yes | Proves federation membership |
| `x-biscuit` | string | No | Grants access to specific skills |
| `x-payment` | JSON | No | Micropayment info (future) |

### Request (JSON-RPC 2.0)

```json
{
  "jsonrpc": "2.0",           // Protocol version
  "id": "string",             // Request ID (echo in response)
  "method": "message",        // Always "message" (A2A task request)
  "params": {                 // task parameters
    "message": "..."          // Natural-language prompt
  }
}
```

### Response (JSON-RPC 2.0)

Success:
```json
{
  "jsonrpc": "2.0",
  "id": "call-123",
  "result": {
    "response": "..."
  }
}
```

Error:
```json
{
  "jsonrpc": "2.0",
  "id": "call-123",
  "error": {
    "code": -32600,
    "message": "Invalid request",
    "data": {
      "details": "..."
    }
  }
}
```

---

## Authentication & Authorization

### Step 1: Authentication (Vouch)

Server receives request with vouch header.

```
vouch = {
  "subject": "alice",
  "peer_id": "12D3Koo...",
  "federation": "finance",
  "issued_at": "2026-04-18",
  "expires_at": "2027-04-18",
  "signature": "..."
}

Server checks:
1. Is vouch signed by a trusted hub?
2. Is vouch expired?
3. Is peer_id in federation vouch database?

If all pass → Proceed to authorization
If any fail → Return error
```

### Step 2: Authorization (Biscuit)

Server checks if caller is allowed the requested skill.

```
biscuit = "alice;allow_skill=weather-bot,risk-audit"

Server checks:
1. Parse biscuit: allowed_skills = ["weather-bot", "risk-audit"]
2. Is requested_skill in allowed_skills?

If yes → Execute skill
If no → Return ErrSkillNotAllowed
```

### Step 3: Execution

Server calls the local agent backend with the skill request.

```
POST http://127.0.0.1:8080
Body: {
  "jsonrpc": "2.0",
  "method": "message",
  "params": {
    "message": "Get forecast"
  }
}

Response: {
  "result": {...}
}

Server returns response to client
```

---

## Error Codes

### A2A Errors

| Code | Reason |
|------|--------|
| `-32600` | Invalid request (malformed JSON) |
| `-32601` | Capability not found |
| `-32603` | Internal server error |

### SAM-Specific Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `ErrNotInFederation` | Vouch not in federation | Authenticate: `sam-agent identity login --hub <url>` |
| `ErrVouchExpired` | Vouch timestamp > expiry | Re-authenticate: `sam-agent identity login --hub <url>` |
| `ErrSkillNotAllowed` | Skill not in Biscuit caveats | Get new Biscuit with skill, or ask for permission |
| `ErrBackendFailed` | Local backend error | Check local backend logs |

---

## Lifespan

### Request-Response Cycle

```
1. Client dials /sam/a2a/1.0 stream
2. Client sends vouch header
3. Server validates vouch (FederationGate)
4. Client sends biscuit header + skill request
5. Server validates biscuit (BiscuitSkillGate)
6. Server executes skill (calls local backend)
7. Server sends response
8. Stream closes
```

### Timeout

Default: 20 seconds (configurable with `--timeout`)

```bash
sam-agent call mycapability --timeout 30s
```

---

## Code Example: Server

```go
// A2A service handler
func (s *A2AService) handleStream(stream libp2pnet.Stream) error {
    ctx := context.Background()
    defer stream.Close()

    // 1. Read vouch from headers
    vouchJSON := stream.Header("x-vouch")
    
    // 2. Parse vouch
    vouch, err := parseVouch(vouchJSON)
    if err != nil {
        return fmt.Errorf("parsing vouch: %w", err)
    }

    // 3. Authenticate (Federation Gate)
    peerID := stream.Conn().RemotePeer()
    capability := getCapabilityFromRequest(stream)
    
    if err := s.gate.Allow(ctx, peerID, capability); err != nil {
        return fmt.Errorf("federation gate: %w", err)
    }

    // 4. Read biscuit from headers
    biscuitToken := stream.Header("x-biscuit")
    
    // 5. Authorize (Biscuit Gate)
    if s.skillGate != nil {
        if err := s.skillGate.CheckSkill(ctx, biscuitToken, capability); err != nil {
            return fmt.Errorf("skill gate: %w", err)
        }
    }

    // 6. Read request body
    var req protocol.A2ARequest
    if err := json.NewDecoder(stream).Decode(&req); err != nil {
        return fmt.Errorf("decoding request: %w", err)
    }

    // 7. Execute skill (call local backend)
    resp, err := s.executeBackend(ctx, capability, req.Params)
    if err != nil {
        return fmt.Errorf("executing skill: %w", err)
    }

    // 8. Send response
    return json.NewEncoder(stream).Encode(resp)
}
```

### Code Example: Client

```go
// A2A call from client
func callRemoteSkill(ctx context.Context, host host.Host, target peer.ID, skill string) error {
    // 1. Open stream
    stream, err := host.NewStream(ctx, target, "/sam/a2a/1.0")
    if err != nil {
        return fmt.Errorf("opening stream: %w", err)
    }
    defer stream.Close()

    // 2. Get local vouch
    vouch, err := loadLocalVouch()
    if err != nil {
        return err
    }

    // 3. Create biscuit token
    biscuit := "alice;allow_skill=" + skill

    // 4. Build request
    req := &A2ARequest{
        JSONRPC: "2.0",
        ID:      "call-123",
        Method:  "message",
        Params: map[string]interface{}{
            "message": "Execute skill",
        },
    }

    // 5. Send headers
    stream.SetHeader("x-vouch", mustMarshal(vouch))
    stream.SetHeader("x-biscuit", biscuit)

    // 6. Send request
    if err := json.NewEncoder(stream).Encode(req); err != nil {
        return fmt.Errorf("sending request: %w", err)
    }

    // 7. Read response
    var resp A2AResponse
    if err := json.NewDecoder(stream).Decode(&resp); err != nil {
        return fmt.Errorf("reading response: %w", err)
    }

    if resp.Error != nil {
        return fmt.Errorf("A2A error: %v", resp.Error)
    }

    return nil
}
```

---

## Stream Lifecycle

### TCP-like Semantics

A2A streams behave like TCP connections:
- **Connect**: Open stream to remote peer
- **Send**: Write request JSON
- **Receive**: Read response JSON
- **Close**: Stream closes after response

### Multiple Calls

To make multiple calls efficiently:
```go
// Open connection once
stream, err := host.NewStream(ctx, target, "/sam/a2a/1.0")

// Make multiple calls on same stream (future feature)
// Currently: one call per stream
```

---

## Network Considerations

### Bandwidth

A2A requests are lightweight:
- Request: ~200 bytes (JSON-RPC header + small prompt)
- Response: Variable (depends on result size)

### Latency

Typical A2A call latency:
- DHT discovery: 500ms - 5s (cached after first call)
- Stream setup: 50-200ms
- RPC roundtrip: 100-500ms
- Backend execution: 1-10s (depends on implementation)
- **Total**: 2-15 seconds

### Firewalls

If direct connection fails, libp2p automatically:
1. Attempts hole-punch (DCUtR)
2. Falls back to relay
3. Stream still works (just slower)

---

## Future Enhancements

1. **Streaming Responses**: For large result sets
2. **Batch Requests**: Multiple calls in one stream
3. **Subscribe Pattern**: Stream-based subscriptions (not request-response)
4. **Compression**: Gzip compression for large payloads
5. **Signature**: Sign requests with client key (not just vouch)

---

## Specification Status

**Current**: Implemented in Go, tested with BATS and integration tests

**Future**: Standardize as IETF RFC or similar

**Stability**: Protocol is stable; APIs may change before v1.0

---

## Related Concepts

- **[Vouch](#/concepts/identity.md)**: Authentication mechanism
- **[Biscuit](#/concepts/biscuit.md)**: Authorization mechanism
- **[Federation](#/concepts/federation.md)**: Network isolation
- **[CLI](#/cli/reference.md)**: How to invoke A2A calls

---

## Next Steps

- **[Try it Out](#/guides/dark-mesh.md)**: Make your first A2A call
- **[Integration Tests](https://github.com/aojea/sam/tree/main/tests/integration)**: See A2A in action
- **[Contributing](#/contributing.md)**: Help improve the protocol
