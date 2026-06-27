# SAM Policy & Authorization Reference

SAM uses a decentralized authorization model powered by [Biscuit](https://www.biscuitsec.org/). 
The `sam-hub` authenticates users via OIDC and injects **Facts** into their token based on `policies.yaml`. The `sam-node` operates offline, evaluating the token against baseline rules and optional local attenuation policies.

## 1. OIDC to Biscuit Translation
The Hub automatically translates OIDC claims into undeniable cryptographic facts:

| OIDC Claim / Data | Biscuit Fact | Description |
| :--- | :--- | :--- |
| `sub` | `user("<sub-id>")` | The unique subject ID from the identity provider. |
| `email` | `email("<email>")` | The user's email address (if present). |
| `groups` / `roles` | `role("<role-name>")` | One fact is injected for *each* role/group the user possesses. |
| Generated FQDN | `name("<fqdn>")` | The collision-proof mesh name granted by the Hub. |
| Peer ID | `node("<peer-id>")` | Binds the token to the specific agent's libp2p cryptographic identity. |
| Expiration | `time(<date>)` | The token expiration date based on the OIDC session. |

## 2. Hub Policy Schema (`policies.yaml`)
Admins define central permissions by mapping OIDC roles to specific capabilities.

```yaml
version: "v1alpha1"
roles:
  data-scientist:
    network:
      allowed_targets: ["db-agent.data-mesh"] # Who they can connect to
    mcp:
      allowed_tools: ["query_database"] # What tools they can run
    custom_datalog:
      - 'department("analytics");' # Raw injected facts
```

## 3. Node Local Attenuation Schema (`local_policy.yaml`)
Local developers can further restrict access to their specific node. Local policies can only attenuate (restrict) access, never expand it beyond what the Hub allowed.

```yaml
version: "v1alpha1"
attenuation:
  rules:
    - 'deny if user("untrusted_sub_id");'
  checks:
    - 'check if time($time), $time < 2026-12-31T00:00:00Z;'
```
