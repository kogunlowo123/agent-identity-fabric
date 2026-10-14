# Architecture

## System context (C4 level 1)

```mermaid
C4Context
  title Agent Identity Fabric
  Person(registrar, "Agent registrar", "Platform team member")
  Person(secops, "Security officer", "Suspends and revokes agents")
  System(fabric, "Agent Identity Fabric", "Identity, credentials, delegation, authorization, audit")
  System_Ext(agents, "AI agents", "Workloads on Kubernetes")
  System_Ext(k8s, "Kubernetes OIDC issuer", "Projected service-account tokens")
  System_Ext(idp, "Enterprise IdP", "Entra ID / Okta / Google")
  System_Ext(rs, "Resource servers and MCP/A2A gateway", "Enforce decisions")
  System_Ext(siem, "SIEM", "Audit and alerts")
  Rel(registrar, fabric, "Registers agents", "OIDC")
  Rel(secops, fabric, "Lifecycle control", "OIDC")
  Rel(agents, fabric, "Attest, obtain and exchange credentials")
  Rel(fabric, k8s, "Fetch JWKS")
  Rel(fabric, idp, "Fetch JWKS")
  Rel(rs, fabric, "Introspect, authorize, JWKS")
  Rel(fabric, siem, "Audit chains, metrics, traces")
```

## Containers (C4 level 2)

```mermaid
flowchart LR
  subgraph cluster[Kubernetes namespace agent-identity]
    api[FastAPI service<br/>StatefulSet x3]
    pvc[(Per-replica audit volume)]
  end
  db[(Managed PostgreSQL<br/>agents, revocations)]
  sm[Secret manager<br/>DB URL, signing keys, audit key]
  worm[(WORM object storage<br/>audit chains)]
  otel[OTel collector]
  api --> db
  sm -- External Secrets --> api
  api --> pvc -- log shipper --> worm
  api --> otel
```

## Components (C4 level 3)

| Layer | Module | Responsibility |
|---|---|---|
| API | `api.routes`, `api.app` | HTTP contract, OAuth wire formats, admin authentication, correlation IDs, metrics |
| Application | `application.service.IdentityFabric` | Use cases: register, attest, issue, exchange, validate, introspect, revoke, authorize; audit every outcome |
| Domain | `domain.models` | Agent aggregate and lifecycle state machine, delegation chain, credential claims |
| Security | `security.tokens`, `keys`, `attestation`, `jwks`, `admin` | Signing and verification, key ring, workload attestation, remote JWKS caching, admin OIDC |
| Infrastructure | `infrastructure.database` | SQLAlchemy Core repositories (PostgreSQL in production) |
| Runtime | `runtime.container` | Composition root; builds everything from settings |

## Sequences

### Registration and attestation

```mermaid
sequenceDiagram
  participant R as Registrar
  participant F as Fabric
  participant W as Agent workload
  participant K as Cluster OIDC issuer
  R->>F: POST /v1/agents (mandate, scopes, workload binding) + OIDC token
  F->>F: verify role agent-registrar; issuer trusted?
  F-->>R: 201 status=pending (audited)
  W->>F: POST /v1/attest (projected SA token)
  F->>K: GET JWKS (cached)
  F->>F: verify signature, iss, aud, sub == binding, image digest allowed
  F-->>W: status=active (audited)
```

### Credential issuance and delegation

```mermaid
sequenceDiagram
  participant A as Orchestrator agent
  participant B as Scheduler agent
  participant F as Fabric
  participant G as Gateway / resource server
  A->>F: POST /oauth2/token grant=jwt-bearer (workload token)
  F-->>A: EdDSA JWT, 10 min, scopes ⊆ registration
  A->>B: hands over task + its credential
  B->>F: POST /oauth2/token grant=token-exchange (subject=A, actor=B)
  F->>F: validate both, scopes = A ∩ B ∩ request, depth ≤ 3, exp ≤ A.exp, no cycle
  F-->>B: credential sub=A act={sub:B}
  B->>G: call tool with delegated credential
  G->>F: POST /v1/authorize
  F->>F: validate chain (every agent active, epochs current), policy, classification ceiling
  F-->>G: allow / deny / require_approval + policy digest (audited)
```

### Suspension

Suspension increments the agent's credential epoch. Every token carries the
epoch it was issued under, so all outstanding credentials fail validation
immediately, including delegated tokens where the suspended agent appears
anywhere in the chain. No token list needs to be enumerated.

## Deployment view

```mermaid
flowchart TB
  subgraph region[Cloud region]
    subgraph az1[Zone A]
      p1[fabric-0]
    end
    subgraph az2[Zone B]
      p2[fabric-1]
    end
    subgraph az3[Zone C]
      p3[fabric-2]
    end
    lb[Ingress / internal LB] --> p1 & p2 & p3
    p1 & p2 & p3 --> pg[(PostgreSQL HA<br/>multi-zone)]
    p1 & p2 & p3 --> bucket[(WORM bucket)]
  end
```

Replicas are spread across zones (topology spread constraints); the PDB keeps
two available during voluntary disruption; PostgreSQL runs zone-redundant.

## Data

| Store | Data | Classification | Retention |
|---|---|---|---|
| PostgreSQL `agents` | Registration, mandate, lifecycle state | INTERNAL | Life of agent + 7 years (records) |
| PostgreSQL `revoked_tokens` | Token IDs and expiry | INTERNAL | Until token expiry (purged every 15 min) |
| Audit chains | Who did what, under which policy | CONFIDENTIAL | 7 years, WORM |
| Signing keys | Ed25519 private keys | SECRET | Rotated every 90 days |

Credentials and workload tokens are never persisted or logged.
