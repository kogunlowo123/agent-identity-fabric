# Configuration reference

All settings are `FABRIC_*` environment variables (see `src/identity_fabric/config.py`).
The service refuses to start with incomplete configuration.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FABRIC_ENVIRONMENT` | no | `production` | `production` forbids ephemeral keys |
| `FABRIC_TRUST_DOMAIN` | yes | | SPIFFE trust domain |
| `FABRIC_ISSUER` | yes | | Public URL; `iss` of credentials |
| `FABRIC_AUDIENCE` | no | `agent-platform` | `aud` of credentials |
| `FABRIC_DATABASE_URL` | yes | | SQLAlchemy async URL |
| `FABRIC_SIGNING_KEYS_DIR` | yes* | | Directory of `<kid>.pem` Ed25519 keys |
| `FABRIC_ACTIVE_KID` | yes* | | Kid used for signing |
| `FABRIC_AUDIT_KEY_FILE` | yes* | | Ed25519 PEM for audit signatures |
| `FABRIC_AUDIT_LOG_PATH` | no | `/var/lib/identity-fabric/audit/audit.jsonl` | Audit chain file |
| `FABRIC_DEV_EPHEMERAL_KEYS` | no | `false` | In-memory keys, non-production only (replaces the three * settings) |
| `FABRIC_WORKLOAD_ISSUERS` | yes | | JSON object: issuer URL → JWKS URL |
| `FABRIC_ADMIN_ISSUER` | yes | | Enterprise OIDC issuer |
| `FABRIC_ADMIN_AUDIENCE` | yes | | Audience of admin tokens |
| `FABRIC_ADMIN_JWKS_URL` | yes | | Enterprise IdP JWKS |
| `FABRIC_ADMIN_ROLES_CLAIM` | no | `roles` | Claim carrying admin roles |
| `FABRIC_POLICY_FILE` | no | `policies/agent-authorization.yaml` | Authorization policy |
| `FABRIC_TOKEN_TTL_SECONDS` | no | `600` | 60–900 |
| `FABRIC_MAX_TOKEN_TTL_SECONDS` | no | `900` | 60–3600 |
| `FABRIC_MAX_DELEGATION_DEPTH` | no | `3` | 1–10 |
| `FABRIC_LOG_LEVEL` | no | `INFO` | |
| `FABRIC_OTLP_ENDPOINT` | no | | OTLP gRPC endpoint for traces |
| `FABRIC_HOST` / `FABRIC_PORT` | no | `127.0.0.1` / `8080` | Container image sets host `0.0.0.0` |
| `FABRIC_FORWARDED_ALLOW_IPS` | no | `127.0.0.1` | Proxies trusted for `X-Forwarded-*` |
