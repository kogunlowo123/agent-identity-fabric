# ADR-0002: Attest agents with platform-issued workload tokens

- Status: Accepted
- Date: 2026-10-14

## Context

A client secret per agent is a credential that can be copied, leaked into
prompts or logs, and replayed from anywhere. The platform already proves
workload identity: Kubernetes projects audience-bound, short-lived
service-account tokens; EKS, AKS and GKE federate those to cloud IAM; SPIRE
issues JWT-SVIDs.

## Decision

Agents never hold a static secret. To activate (and on every credential
request) an agent presents its workload token. The fabric verifies it against
the registered issuer's JWKS and checks:

1. `iss` is a trusted issuer configured by operators;
2. `aud` equals the audience in the registration (so tokens minted for other
   services are useless here);
3. `sub` equals the registered service account;
4. the reported image digest is on the registration's allow list, when one is
   set.

Identities are SPIFFE IDs so the same names work with SPIRE if a deployment
adopts it.

## Consequences

- Stealing an agent's credential gives at most 15 minutes of access, and a
  credential cannot be renewed without running as the bound workload.
- Image-digest pinning requires the admission pipeline to surface the digest
  in the token claims; when absent, pinning is disabled for that agent by
  leaving the list empty.
