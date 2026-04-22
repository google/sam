# Biscuit Authorization: Fine-Grained Access Control

## The Problem: All-or-Nothing Access

Traditional systems either grant full access or none:

```
Partner API Key: alice-key-123
├── Can call ANY endpoint
└── No granular access control

Issue: If the key leaks, attacker gets full access
```

SAM uses **Biscuit tokens** to grant access to specific skills only.

---

## What is a Biscuit Token?

A Biscuit is a **lightweight credential with caveats** (restrictions).

### Format

```
<subject>;<caveat>=<value>,<value>
```

### Example

```
alice;allow_skill=weather-bot
```

Breakdown:
- **Subject**: `alice` (who the token is for)
- **Caveat**: `allow_skill` (what type of restriction)
- **Values**: `weather-bot` (specific skills allowed)

### Multiple Skills

```
alice;allow_skill=weather-bot,risk-audit,email-send
```

Allows: weather-bot, risk-audit, email-send
Denies: everything else

### No Skills (Unrestricted)

```
alice
```

No caveat = full access to all skills

---

## Why Plain Text?

SAM uses plain-text Biscuits instead of cryptographic ones because:

1. **Transparency**: Anyone can read what permissions are granted
2. **Auditability**: `sam inspect biscuit` decodes without a server
3. **Lightweight**: No cryptography overhead for authorization
4. **Revocable**: Just delete the token from the app

**Trade-off:** Plain-text Biscuits can be modified by the client, but SAM assumes:
- Client trusts their own OS (local isolation)
- Tokens are shared only with trusted applications
- Server can verify trust via A2A authentication first

---

## Authorization Flow

### Step 1: Grant Access

Alice creates a Biscuit for partner-bot:

```bash
TOKEN="partner-bot@vendor.com;allow_skill=risk-audit"
# Shared via secure channel (email, encrypted message, etc)
```

### Step 2: Client Uses Token

Partner-bot calls alice's agent:

```bash
sam-agent call risk-audit \
  --biscuit "partner-bot@vendor.com;allow_skill=risk-audit" \
  --message "Audit my data"
```

### Step 3: Server Verifies

Alice's agent:

1. Receives the Biscuit token
2. Parses it: `ParsedBiscuit{Subject: "partner-bot", AllowedSkills: ["risk-audit"]}`
3. Checks: Is `risk-audit` in `AllowedSkills`?
4. **Yes** → Execute skill
5. **No** → Reject with `ErrSkillNotAllowed`

### Step 4: Enforce Fine-Grained Access

Partner-bot tries to use a different skill:

```bash
sam-agent call compliance-check \
  --biscuit "partner-bot@vendor.com;allow_skill=risk-audit" \
  --message "Check compliance"
```

Alice's agent:

1. Parses token: `AllowedSkills: ["risk-audit"]`
2. Checks: Is `compliance-check` in `AllowedSkills`?
3. **No** → Return error: `ErrSkillNotAllowed`

---

## Biscuit Parsing

### SimpleB iscuitParser

SAM uses a simple parser that handles plain-text Biscuits:

```go
type SimpleBiscuitParser struct {}

func (p *SimpleBiscuitParser) Parse(ctx context.Context, token string) (*ParsedBiscuit, error) {
    // Format: subject;allow_skill=skill1,skill2,...
    
    parts := strings.Split(token, ";")
    
    biscuit := &ParsedBiscuit{
        Subject: strings.TrimSpace(parts[0]),
        AllowedSkills: []string{},
    }
    
    if len(parts) < 2 {
        return biscuit, nil  // No caveat = unrestricted
    }
    
    // Parse caveat: allow_skill=skill1,skill2
    caveatParts := strings.Split(parts[1], "=")
    if caveatParts[0] != "allow_skill" {
        return nil, ErrUnknownCaveat
    }
    
    skills := strings.Split(caveatParts[1], ",")
    for _, skill := range skills {
        if s := strings.TrimSpace(skill); s != "" {
            biscuit.AllowedSkills = append(biscuit.AllowedSkills, s)
        }
    }
    
    return biscuit, nil
}
```

### ParsedBiscuit Structure

```go
type ParsedBiscuit struct {
    Subject string          // "alice"
    AllowedSkills []string  // ["weather-bot", "risk-audit"]
}
```

---

## Skill Gate: Enforcement

When a call arrives, the **BiscuitSkillGate** enforces the caveat:

```go
type BiscuitSkillGate struct {
    parser BiscuitParser
}

func (g *BiscuitSkillGate) CheckSkill(ctx context.Context, token string, skill string) error {
    parsed, err := g.parser.Parse(ctx, token)
    if err != nil {
        return err
    }
    
    // If no skills are restricted, allow all
    if len(parsed.AllowedSkills) == 0 {
        return nil
    }
    
    // Check if requested skill is allowed
    for _, allowed := range parsed.AllowedSkills {
        if allowed == skill {
            return nil
        }
    }
    
    return ErrSkillNotAllowed
}
```

---

## A2A Stream Handling with Biscuit

When a call arrives on the A2A stream:

```go
func (s *A2AService) handleStream(stream libp2pnet.Stream) error {
    peerID := stream.Conn().RemotePeer()
    
    // 1. Federation Gate: Check vouch (authentication)
    if err := s.gate.Allow(ctx, peerID, capability); err != nil {
        return fmt.Errorf("federation gate: %w", err)
    }
    
    // 2. Read Biscuit token from stream headers
    biscuitToken := stream.Header("x-biscuit")
    
    // 3. Biscuit Gate: Check skill (authorization)
    if s.skillGate != nil {
        if err := s.skillGate.CheckSkill(ctx, biscuitToken, capability); err != nil {
            return fmt.Errorf("skill gate: %w", err)
        }
    }
    
    // 4. Execute the skill
    return s.executeSkill(ctx, capability, payload)
}
```

---

## Use Cases

### Use Case 1: Partner Access (Read-Only)

```bash
# Grant vendor access to audit skill only
VENDOR_TOKEN="vendor@external.com;allow_skill=audit"

# Vendor can use this skill
sam call audit --biscuit "$VENDOR_TOKEN"

# Vendor cannot use other skills
sam call delete-data --biscuit "$VENDOR_TOKEN"  # ✗ Error: skill not allowed
```

### Use Case 2: Multiple Skills (Limited Scope)

```bash
# Grant contractor access to specific tools
CONTRACTOR_TOKEN="contractor@acme.corp;allow_skill=log-query,metric-check"

# Contractor can use these
sam call log-query --biscuit "$CONTRACTOR_TOKEN"      # ✓ OK
sam call metric-check --biscuit "$CONTRACTOR_TOKEN"   # ✓ OK

# Contractor cannot use others
sam call deploy --biscuit "$CONTRACTOR_TOKEN"         # ✗ Error: not in allow list
```

### Use Case 3: Unrestricted Token (Trusted Partner)

```bash
# Grant trusted partner full access (no caveat)
PARTNER_TOKEN="partner@trusted.com"

# Partner can use ANY skill
sam call risk-audit --biscuit "$PARTNER_TOKEN"        # ✓ OK
sam call weather --biscuit "$PARTNER_TOKEN"           # ✓ OK
sam call deploy --biscuit "$PARTNER_TOKEN"            # ✓ OK (all allowed)
```

---

## Inspecting Tokens

Before sharing a token, verify what it grants:

### Single Skill

```bash
sam inspect biscuit "alice;allow_skill=weather-bot"
```

Output:
```
Biscuit Token Analysis
======================

Subject: alice
Allowed Skills: weather-bot

Human-Readable Summary:
This token issued to 'alice' allows execution of 'weather-bot' skill only.
```

### Multiple Skills

```bash
sam inspect biscuit "partner;allow_skill=risk-audit,compliance-check"
```

Output:
```
Biscuit Token Analysis
======================

Subject: partner
Allowed Skills: 
  - risk-audit
  - compliance-check

Human-Readable Summary:
This token issued to 'partner' allows execution of 2 skills:
risk-audit, compliance-check.
```

### Unrestricted

```bash
sam inspect biscuit "trusted-partner"
```

Output:
```
Biscuit Token Analysis
======================

Subject: trusted-partner
Allowed Skills: (none, unrestricted)

Human-Readable Summary:
This token issued to 'trusted-partner' allows execution of ALL skills.
```

---

## Token Management

### Creating Tokens

Tokens are not generated by a server; they're created locally:

```bash
# CLI (future): Create a token
sam economy biscuit create \
  --subject "vendor@external.com" \
  --allow-skill risk-audit \
  --allow-skill weather-bot
```

Or manually:
```bash
TOKEN="vendor@external.com;allow_skill=risk-audit,weather-bot"
```

### Sharing Tokens

Tokens should be shared via secure channels:
- Encrypted email
- Secure messaging app
- In-person (QR code)
- Not in logs, not in URLs, not in Git

### Revoking Tokens

Tokens are revoked by **removing them from use**:

```bash
# In your application configuration
echo "vendor@external.com;allow_skill=risk-audit" > revoked-tokens.txt
```

Then check against revoked list before allowing:

```go
if isRevoked(token) {
    return ErrTokenRevoked
}
```

### Token Lifetime

By default, Biscuits have **no expiry**. To implement expiry:

1. Add an optional caveat: `alice;allow_skill=weather-bot;expires=2027-04-18`
2. Check expiry in the gate: `CheckSkill()` validates expiry
3. Revoke after expiry

---

## Limitations and Future Work

### Current Limitations

1. **Plain-text**: Client can modify token (mitigated by OS isolation)
2. **No signature**: Server trusts client's assertion (mitigated by A2A auth first)
3. **No expiry**: Tokens don't auto-expire (revoke manually)
4. **No delegation**: Can't delegate further ("partner gives token to sub-partner")

### Future Enhancements

1. **Cryptographic Biscuits**: Sign tokens with issuer key
2. **Expiry Caveats**: `allow_skill=X;expires=<timestamp>`
3. **Delegation**: Allow `partner` to grant subsets to others
4. **Revocation List**: Server-side revocation (traded for offline capability)

---

## Integration with A2A Protocol

### Request Flow

```
Client                           Server
   │                               │
   ├─ Connect A2A stream          │
   ├─────────────────────────────>│
   │                               │
   ├─ Send Vouch (authentication) │
   ├─────────────────────────────>│
   │                               │
   ├─ Send Biscuit (authorization)│
   ├─────────────────────────────>│
   │                               │
   │   [FederationGate checks]    │
   │   [BiscuitSkillGate checks]  │
   │                               │
   │                     [Execute]│
   │                               │
   │<───────────────────────────── │ Response
```

### Code Example

```go
// Client prepares call
vouch := loadVouch(federation)
biscuit := "partner;allow_skill=risk-audit"
capability := "risk-audit"

// Server validates
gate := NewVouchGate(store)
if err := gate.Allow(ctx, peerID, capability); err != nil {
    return err  // Not in federation
}

skillGate := NewBiscuitSkillGate(parser)
if err := skillGate.CheckSkill(ctx, biscuit, capability); err != nil {
    return err  // Not in allowed_skills
}

// Execute
return executeSkill(ctx, capability, payload)
```

---

## Security Considerations

### Trust Assumptions

1. **Client OS is secure**: Tokens are stored in plaintext
2. **Client network is secure**: Tokens sent over libp2p TLS
3. **Server trusts A2A authentication first**: Biscuit is secondary check
4. **Tokens are not long-lived**: Regular rotation recommended

### Attack Scenarios

| Scenario | Risk | Mitigation |
|----------|------|-----------|
| Token leaked | Attacker uses skill | Revoke token, re-authenticate |
| Client compromised | Attacker modifies token | OS isolation, encryption |
| Server compromised | Attacker sees skills | Caveats are read-only, don't leak secrets |
| Token replayed | Attacker reuses token | Signature + nonce (future) |

---

## Next Steps

- **[Identity & Vouch System](#/concepts/identity.md)**: How authentication works
- **[A2A Protocol](#/concepts/a2a-protocol.md)**: How authorization is enforced
- **[CLI Reference](#/cli/reference.md)**: `sam inspect biscuit` usage
