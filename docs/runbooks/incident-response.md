# Runbook: incident response

## Compromised or misbehaving agent

1. Suspend immediately (all outstanding credentials stop validating):
   ```bash
   curl -X POST "$FABRIC/v1/suspend?agent_uri=<spiffe-id>" \
     -H "Authorization: Bearer $SECOPS_TOKEN" -H 'content-type: application/json' \
     -d '{"reason":"INC-<number>: <summary>"}'
   ```
2. Confirm: `POST /oauth2/introspect` with a captured token returns
   `{"active": false}`.
3. Pull the agent's audit trail from WORM storage and filter by `actor` or
   `resource` equal to the SPIFFE ID; collect delegation chains (`chain`) to
   find downstream agents that acted on its behalf.
4. Revoke (`/v1/revoke-agent`) if the agent will not return. Revocation is
   terminal; re-registration creates a new identity.

## Attestation failures

Alert `FabricAttestationFailureSpike`. Sustained `invalid_grant` means
workloads are presenting tokens that do not match registrations.

1. Group failures by agent: search audit for `action="token.issue"`,
   `outcome="denied"`.
2. Legitimate cause: a deployment changed service account or image digest.
   Update the registration through change control.
3. Otherwise treat as impersonation: suspend the targeted agent, inspect the
   source pods (NetworkPolicy logs), rotate the cluster's service-account
   signing key if a token leak is suspected.

## Elevated 5xx

1. `kubectl -n agent-identity get pods`; check `/readyz` per pod.
2. Readiness failing: database. Check managed PostgreSQL status and
   failover events.
3. Pods crash-looping on start: configuration. `kubectl logs` shows the
   failing setting (the service refuses to start on incomplete config).
4. If a release caused it, follow the rollback runbook.

## Deny spike

A jump in denials after a policy change is expected to be the policy change.
Compare `policy_digest` in recent decisions with the previous release, and
revert the policy commit if unintended.

## Replicas down

Fewer than two replicas scraped. Check node pressure and PDB status; the
fabric tolerates one replica for capacity but loses zone redundancy.

## Signing key compromise

Follow docs/runbooks/key-rotation.md, section "Emergency rotation".
