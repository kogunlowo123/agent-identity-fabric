# ADR-0001: Short-lived EdDSA JWTs with credential epochs

- Status: Accepted
- Date: 2026-10-14

## Context

Agents call tools at high rates. Resource servers need to verify credentials
locally without a round trip, but the enterprise also needs to cut an agent
off immediately when it misbehaves. Long-lived opaque tokens need a lookup on
every call; long-lived JWTs cannot be revoked quickly.

## Decision

- Credentials are JWTs signed with Ed25519 (EdDSA): small signatures, fast
  verification, no algorithm-confusion surface (we accept exactly one alg).
- Lifetime defaults to 10 minutes and is capped at 15.
- Each agent has a `credential_epoch`, embedded in every token. Suspension or
  revocation increments it, so the fabric rejects every outstanding token for
  that agent at the next validation without enumerating tokens.
- Individual tokens can still be revoked by `jti` (RFC 7009); the revocation
  table only holds entries until the token would have expired.

Resource servers that cannot tolerate up to 15 minutes of staleness call
`/oauth2/introspect` or `/v1/authorize`, which apply the epoch and revocation
checks; others verify locally against the JWKS.

## Consequences

- Local verification gives low latency; introspection gives immediacy where
  it matters. Gateways in this portfolio use `/v1/authorize`.
- The revocation table stays small (bounded by issuance rate × 15 minutes).
