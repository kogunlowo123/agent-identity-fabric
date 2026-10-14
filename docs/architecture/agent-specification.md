# Agent specification

The fabric is itself a privileged platform service. This document states its
mandate in the same terms it requires of every agent it registers, and
defines the specification every registered agent must provide.

## The fabric

### Role and mission

- **Purpose:** be the single authority for which AI agents exist, what each
  may do, and on whose behalf.
- **Business objective:** let the enterprise deploy agents against regulated
  systems with the same accountability expected of human users.
- **Protected resources:** agent inventory, signing keys, revocation state,
  audit evidence.
- **Operating boundaries:** issues credentials only to attested workloads;
  never executes agent actions; never stores credentials.
- **Delegated responsibility:** authorization decisions are delegated to the
  versioned policy set owned by AI governance.

### Delegated scope

| Allowed | Disallowed | Escalation |
|---|---|---|
| Issue credentials within registered scopes | Widen any scope beyond registration | Attestation failure spike pages security |
| Exchange tokens with attenuation | Delegate beyond depth 3 or past parent expiry | Delegated writes return `require_approval` |
| Decide authorization per policy | Allow access above an agent's classification ceiling | Critical-risk agents always require approval |

Risk classification of fabric operations: registration MODERATE,
suspension/revocation HIGH, key rotation CRITICAL (change-managed, two-person).

### Objectives

| Type | Definition | Target |
|---|---|---|
| SLO availability | Non-5xx share of `/oauth2/*` and `/v1/authorize` | 99.95% over 30 days |
| SLO latency | p99 `/v1/authorize` | < 100 ms |
| SLO latency | p99 `/oauth2/token` | < 250 ms |
| SLI | `fabric:request_errors:ratio_5m`, latency histograms | Prometheus |
| KPI | Share of production agents registered with attestation | 100% |
| KPI | Mean time from revocation to credential rejection | < 1 s (epoch check) |
| Completion | A request is complete when its outcome is in the signed audit chain | Enforced: audit failure fails the request |

### Permissions

| Mechanism | Use |
|---|---|
| RBAC | Admin roles `agent-registrar`, `agent-security-officer`, `agent-auditor` from the enterprise IdP |
| ABAC | `/v1/authorize` evaluates subject (status, scopes, risk, delegation), resource (type, classification, attributes), environment |
| Agent identity | SPIFFE IDs |
| OAuth 2.0 / OIDC | RFC 7523, 8693, 7662, 7009; admin OIDC |
| Workload identity | Projected service-account tokens; cloud workload identity for the fabric's own cloud access |

### Inputs and outputs

All request and response bodies are Pydantic models with JSON Schemas in
`schemas/`. Inputs reject unknown fields (`extra="forbid"`), scopes must
match `resource:action[:qualifier]`, image digests must be `sha256:<64 hex>`.
Every output that records a decision carries the policy version and digest;
every state change produces an audit event with actor, resource, outcome and
correlation ID.

## What every registered agent must provide

`POST /v1/agents` enforces:

| Field | Meaning |
|---|---|
| `mandate.mission` | Purpose and business objective (10–2000 chars) |
| `mandate.business_owner`, `technical_owner` | Accountable owners |
| `mandate.protected_resources` | Resources the agent touches |
| `mandate.disallowed_actions` | Explicit exclusions |
| `mandate.escalation_contact` | Who is paged when it misbehaves |
| `scopes` | Allowed tasks as scopes |
| `risk` | LOW, MODERATE, HIGH, CRITICAL |
| `max_classification` | Highest data classification it may reach |
| `workload` | Issuer, subject, audience and optional image digests that may claim the identity |
