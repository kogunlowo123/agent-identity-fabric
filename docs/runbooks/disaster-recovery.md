# Runbook: disaster recovery

| Objective | Target | Mechanism |
|---|---|---|
| RPO | ≤ 5 minutes | Managed PostgreSQL point-in-time recovery |
| RTO | ≤ 1 hour | Terraform + Helm redeploy in the recovery region |

## State that matters

- **PostgreSQL**: agent registry and revocations. Restore with PITR.
- **Signing keys**: in the secret manager (replicated per cloud configuration).
- **Audit chains**: in WORM storage (geo-redundant). Not needed to serve
  traffic.

Revocation entries lost to RPO are covered by credential lifetimes (≤ 15 min)
and by epochs, which live in the agent registry.

## Procedure

1. Restore PostgreSQL to the latest point before the incident (cloud console
   or CLI); note the new endpoint.
2. Update the database URL secret if the endpoint changed.
3. `terraform apply` in the recovery region if the cluster region is lost.
4. `helm upgrade --install` with the same values.
5. Verify `/readyz`, list agents, issue a credential for a canary agent.
6. Verify audit chain continuity: new chains start at sequence 0 on new
   volumes; record the cutover in the incident ticket.

Recovery is exercised quarterly by restoring a PITR copy into a staging
namespace and running `tests/e2e` against it.
