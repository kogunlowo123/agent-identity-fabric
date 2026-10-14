# Threat model

## Assets

| Asset | Impact if compromised |
|---|---|
| Signing keys | Forge credentials for any agent |
| Agent inventory and mandates | Unauthorized agents admitted or scopes widened |
| Revocation state / epochs | Revoked agents regain access |
| Audit chains | Loss of accountability; regulatory breach |
| Admin access | All of the above |

## Trust boundaries

1. Agents and resource servers → fabric API (network, untrusted callers).
2. Fabric → workload issuer and enterprise IdP JWKS endpoints.
3. Fabric → PostgreSQL and secret store.
4. Fabric → audit storage.

## STRIDE

| ID | Threat | Category | Control | Test |
|---|---|---|---|---|
| T1 | Forged credential with guessed `kid` | Spoofing | Ed25519 signature verification against key ring | `tests/security::test_t1_forged_signature` |
| T2 | `alg: none` / algorithm confusion | Spoofing | Exactly one accepted algorithm per verifier | `test_t2_alg_none`, `TestJwks::test_verify_jwt_rejections` |
| T3 | Scope tampering in token payload | Tampering | Signature covers claims | `test_t3_payload_tampering` |
| T4 | Workload token replayed as agent credential | Spoofing | Separate issuer and audience | `test_t4_workload_token_replayed_as_agent_credential` |
| T5 | Replay of expired workload token | Spoofing | `exp` enforced, 30 s skew | `test_t5_expired_workload_token` |
| T6 | Agent requests scopes beyond registration | Elevation | Issuance rejects any scope outside registration | `test_t6_scope_escalation_at_issuance` |
| T7 | One agent's workload claims another identity | Spoofing | `sub` must equal registered service account | `test_t7_cross_agent_workload_token` |
| T8 | Unbounded delegation chains | Elevation | Depth cap; attenuation; parent expiry bound; cycle detection | `test_t8_delegation_depth_limit`, `TestDelegation` |
| T9 | Revoked agent keeps using issued tokens | Elevation | Credential epoch | `test_t9_token_issued_before_revocation_dies` |
| T10 | Audit tampering or credential leakage into audit | Repudiation / disclosure | Signed hash chain; no tokens in audit details | `test_t10_audit_chain_is_intact_after_lifecycle` |
| T11 | Audit write fails silently | Repudiation | Audit failure fails the request | `tests/chaos::test_audit_sink_failure_blocks_issuance` |
| T12 | IdP JWKS outage or spoofed JWKS | DoS / spoofing | HTTPS, cache with stale tolerance, rate-limited refresh, fail closed on unknown keys | `tests/chaos`, `TestJwks` |
| T13 | Enumeration / flooding of token endpoint | DoS | HPA, rate limiting at ingress, rejection metrics and alert | `configs/prometheus/alerts.yaml` |
| T14 | Admin token from wrong tenant or without role | Elevation | Issuer, audience and role checks | `tests/e2e::test_admin_authorization` |

## MITRE ATT&CK (Enterprise) techniques addressed

| Technique | Mitigation |
|---|---|
| T1078 Valid Accounts / T1078.004 Cloud Accounts | Workload attestation, short TTL, epochs |
| T1528 Steal Application Access Token | 15-minute cap, audience binding, revocation |
| T1550.001 Use Alternate Authentication Material: Application Access Token | Introspection with epoch and revocation checks |
| T1552 Unsecured Credentials | No static agent secrets; keys only in secret manager |
| T1098 Account Manipulation | Admin RBAC, audited lifecycle |
| T1562.008 Impair Defenses: Disable Cloud Logs | WORM audit storage, audit-failure fails closed |

## OWASP Top 10 for LLM Applications (2025)

| Risk | Relevance | Control |
|---|---|---|
| LLM06 Excessive Agency | Primary | Scoped credentials, delegation attenuation, approval outcomes, classification ceiling |
| LLM01 Prompt Injection | Indirect: injected instructions try to make agents act | Agents cannot exceed credential scopes regardless of instructions |
| LLM02 Sensitive Information Disclosure | Data access | `max_classification` ceiling enforced outside policy |
| LLM03 Supply Chain | Agent images | Image-digest allow list at attestation |

## OWASP API Security Top 10 (2023)

| Risk | Control |
|---|---|
| API1 Broken Object Level Authorization | Admin routes require role; agents act only on their own identity |
| API2 Broken Authentication | Signed tokens, single algorithm, issuer/audience checks |
| API3 Broken Object Property Level Authorization | `extra="forbid"` on inputs; responses exclude internal fields (epoch) |
| API4 Unrestricted Resource Consumption | List paging limits (≤500), body validation, HPA |
| API5 Broken Function Level Authorization | Distinct roles for registration vs lifecycle control |
| API8 Security Misconfiguration | Production refuses ephemeral keys; Helm `required` values; restricted Pod Security |
| API10 Unsafe Consumption of APIs | JWKS fetched over HTTPS with timeouts and fail-closed parsing |

## Risk register

| ID | Risk | Likelihood | Impact | Owner | Treatment | Residual |
|---|---|---|---|---|---|---|
| R1 | Signing key exfiltration | Low | Critical | Security Ops | Secret manager + KMS, 90-day rotation, emergency rotation runbook | Low |
| R2 | Cluster OIDC issuer compromise | Low | High | Platform | Image digest pinning, short TTL, anomaly alert | Medium |
| R3 | Policy misconfiguration grants excess access | Medium | High | AI Governance | CODEOWNERS on policies, digest in every decision, tests | Low |
| R4 | PostgreSQL outage | Medium | High | Platform | Zone-redundant HA, readiness probe, PITR | Low |
| R5 | Up to 15-minute window for locally verified tokens after revocation | Medium | Medium | Platform | High-risk resources must call `/v1/authorize` | Low |
