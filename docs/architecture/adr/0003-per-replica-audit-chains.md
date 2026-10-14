# ADR-0003: One signed audit chain per replica

- Status: Accepted
- Date: 2026-10-14

## Context

The audit chain (agentic-core ADR-0004) is append-serialized. A single chain
shared by all replicas would need a distributed lock on every request.

## Decision

Run the fabric as a StatefulSet. Each replica writes its own chain to its own
persistent volume (`<pod-name>.jsonl`), signed with the shared audit key. A
log shipper copies chains to WORM object storage (S3 Object Lock, Azure
immutable blobs, GCS retention lock) provisioned by Terraform. Verification
runs per chain; events carry correlation IDs so a request can be followed
across chains.

## Consequences

- No cross-replica coordination on the hot path.
- Scaling down leaves a chain whose PVC is retained (StatefulSet default) and
  already shipped; nothing is lost.
- Auditors verify N chains instead of one; `verify_chain` is per-chain anyway.
