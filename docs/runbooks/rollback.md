# Runbook: rollback

The schema is additive within a minor version (`schema_version` table), so
application rollback within 0.x.y does not require database changes.

```bash
helm -n agent-identity history fabric
helm -n agent-identity rollback fabric <revision> --wait
kubectl -n agent-identity rollout status statefulset/fabric-agent-identity-fabric
curl -sf "$FABRIC/readyz"
```

Policy-only regressions: revert the commit touching
`policies/agent-authorization.yaml`, release, and confirm the
`policy_digest` returned by `/v1/authorize` matches the reverted file.

Rollback is exercised in CI on every change: the chart renders and the
container starts from a clean state; the previous image tag remains in GHCR
for every release.
