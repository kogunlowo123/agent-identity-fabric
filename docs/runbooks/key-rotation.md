# Runbook: signing key rotation

Scheduled every 90 days. Change-managed; two people.

## Scheduled rotation

1. Generate the new key and store it (new kid, e.g. `2027-01`):
   ```bash
   uv run python -m identity_fabric.keygen 2027-01 2> 2027-01.jwk.json \
     | <secret-manager-cli> create agent-identity-fabric-signing-key-2027-01
   ```
2. Wait for External Secrets to sync (≤ 1 h or force:
   `kubectl annotate externalsecret agent-identity-fabric-signing-keys force-sync=$(date +%s) --overwrite`).
3. Publish without signing: roll the StatefulSet with the *old* `activeKid`.
   JWKS now lists both keys, so resource servers cache the new public key.
4. After the longest JWKS cache TTL in your estate (default 5 min here), set
   `fabric.activeKid=2027-01` and `helm upgrade`.
5. After 15 minutes (maximum credential lifetime), delete the old key secret
   and roll again. JWKS lists only the new key.

## Emergency rotation (key compromise)

1. Generate a new key as above.
2. Set `activeKid` to the new kid **and delete the compromised secret in the
   same change**; `helm upgrade`. Tokens signed by the compromised key now
   fail with `unknown signing key`.
3. Every agent re-obtains credentials automatically on its next request
   (workload attestation needs no human action).
4. Review audit chains for credentials issued during the exposure window.

## Audit key rotation

Same procedure with `agent-identity-fabric-audit-key-<kid>` and
`secrets.auditKeyFile`. Retain old audit public keys indefinitely: chains
signed with them must remain verifiable for the retention period.
