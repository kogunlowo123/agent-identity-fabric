# Agent Identity Fabric

Identity and authorization for enterprise AI agents. Every agent gets a
registered identity with a documented mandate, proves which workload it runs
as before it receives credentials, carries short-lived scoped credentials,
can delegate a subset of its authority to another agent with a verifiable
chain, and can be suspended or revoked with immediate effect. Every step is
recorded in a signed, tamper-evident audit chain.

```
Agent ─▶ Registration ─▶ Attestation ─▶ Identity ─▶ Authorization ─▶ Delegation
      ─▶ Execution ─▶ Audit ─▶ Revocation
```

## Capabilities

| Capability | Implementation |
|---|---|
| Agent identity | SPIFFE ID `spiffe://<trust-domain>/agent/<namespace>/<name>` with mandate, owners, scopes, risk tier, data-classification ceiling |
| Workload attestation | Kubernetes projected service-account tokens or cloud workload identity tokens verified against the issuer JWKS; subject binding and image-digest allow list |
| Short-lived credentials | EdDSA (Ed25519) JWTs, default 10 min, hard cap 15 min; RFC 7523 jwt-bearer grant |
| Key rotation | Key ring with `kid`; all keys published at `/.well-known/jwks.json` until retired |
| Delegation | RFC 8693 token exchange; scopes = subject ∩ actor ∩ request; nested `act` chain; depth cap; cannot outlive the parent; cycle detection |
| Authorization | `/v1/authorize` policy decision point (ABAC, deny-overrides, approval outcomes) with a classification ceiling enforced outside policy |
| Revocation | Per-token (RFC 7009) and per-agent; suspension invalidates every outstanding credential through a credential epoch |
| Introspection | RFC 7662 |
| Audit | Hash-chained, Ed25519-signed events per replica, shipped to WORM storage |
| Observability | Prometheus metrics, OpenTelemetry traces, JSON logs with correlation IDs, SLO alerts, Grafana dashboard |

Shared controls (policy engine, audit chain, logging, telemetry) come from
[agentic-core](https://github.com/kogunlowo123/agentic-core).

## Quick start (local)

Requires Docker. No API keys or cloud credentials are needed.

```bash
docker compose up --build
curl -s localhost:8080/.well-known/oauth-authorization-server | jq
```

The compose stack runs PostgreSQL, an OIDC provider standing in for both the
workload issuer and the enterprise IdP, and an OpenTelemetry collector.

## Development

```bash
uv sync
make check        # ruff, black, mypy --strict, bandit, contracts, tests (coverage >= 90%)
make integration  # PostgreSQL integration tests (needs FABRIC_TEST_DATABASE_URL)
```

Test suites: `tests/unit`, `tests/security` (credential attacks mapped to the
threat model), `tests/chaos` (dependency failures), `tests/performance`
(latency budgets; `locustfile.py` for load), `tests/e2e` (full HTTP lifecycle
and a property-based OpenAPI contract test), `tests/integration`
(PostgreSQL).

## API

| Endpoint | Caller | Purpose |
|---|---|---|
| `POST /v1/agents` | Registrar (OIDC role `agent-registrar`) | Register an agent and its mandate |
| `GET /v1/agents`, `GET /v1/agents/{id}` | Registrar, security officer, auditor | Inventory |
| `POST /v1/attest?agent_uri=` | Agent workload | Prove workload identity; activates the agent |
| `POST /v1/suspend`, `/v1/reinstate`, `/v1/revoke-agent` | Security officer | Lifecycle control |
| `POST /oauth2/token` | Agent | jwt-bearer issuance; token-exchange delegation |
| `POST /oauth2/introspect` | Resource servers | Token status |
| `POST /oauth2/revoke` | Agent | Revoke a token |
| `POST /v1/authorize` | Agent / gateway | Policy decision for an action on a resource |
| `GET /.well-known/jwks.json`, `/.well-known/oauth-authorization-server` | Anyone | Discovery |

Full contract: [docs/api/openapi.json](docs/api/openapi.json); JSON Schemas in [schemas/](schemas/).

## Deployment

| Layer | Location |
|---|---|
| Container image | `Dockerfile` (non-root, read-only root filesystem compatible) |
| Helm chart | `deployments/helm/agent-identity-fabric` (StatefulSet, PDB, HPA, NetworkPolicy, ServiceMonitor) |
| Namespace and secret sync | `deployments/kubernetes` (restricted Pod Security, External Secrets) |
| Cloud infrastructure | `deployments/terraform/{aws,azure,gcp}`: managed PostgreSQL, KMS, secret store, WORM audit storage, workload identity |

See [deployment runbook](docs/runbooks/startup.md).

## Documentation

- [Architecture](docs/architecture/overview.md) and [agent specification](docs/architecture/agent-specification.md)
- [ADRs](docs/architecture/adr/)
- [Threat model and risk register](docs/security/threat-model.md)
- [Compliance control mapping](docs/compliance/control-mapping.md)
- Runbooks: [startup](docs/runbooks/startup.md), [monitoring](docs/runbooks/monitoring.md), [incident response](docs/runbooks/incident-response.md), [key rotation](docs/runbooks/key-rotation.md), [rollback](docs/runbooks/rollback.md), [disaster recovery](docs/runbooks/disaster-recovery.md)
- [Configuration reference](docs/operations/configuration.md)

## License

Apache-2.0
