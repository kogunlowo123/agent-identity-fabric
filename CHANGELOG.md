# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-14

### Added

- Agent registry with mandate, owners, scopes, risk tier and classification ceiling.
- Workload attestation against trusted issuer JWKS with subject and image-digest binding.
- EdDSA credentials (RFC 7523 jwt-bearer), token exchange delegation (RFC 8693),
  introspection (RFC 7662) and revocation (RFC 7009).
- Credential epochs for immediate invalidation on suspension or revocation.
- Authorization decision endpoint backed by the agentic-core policy engine.
- Signed per-replica audit chains.
- Helm chart, Kubernetes namespace and secret sync, Terraform for AWS, Azure and GCP.
- CI: lint, types, SAST, contract drift, tests (unit, security, chaos, performance,
  e2e, PostgreSQL integration), Helm/kubeconform, Terraform validate, Trivy,
  Syft, Grype, Semgrep, container smoke test.
