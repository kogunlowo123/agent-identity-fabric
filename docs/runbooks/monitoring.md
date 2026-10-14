# Runbook: monitoring

## Signals

| Signal | Source | Normal |
|---|---|---|
| `fabric:request_errors:ratio_5m` | Prometheus recording rule | < 0.0005 |
| p99 latency by route | `fabric_http_request_duration_seconds` | authorize < 100 ms, token < 250 ms |
| `fabric_token_failures_total{error}` | Prometheus | Low, steady |
| `fabric_authorization_decisions_total{decision}` | Prometheus | Deny share stable per release |
| `fabric_revocations_purged_last` | Prometheus | Non-negative every 15 min |
| Traces | OTLP → tracing backend | Span per request; DB spans |
| Logs | JSON on stdout | `correlation_id` on every line |

Alerts are defined in `configs/prometheus/alerts.yaml`.

## Latency

1. Check the dashboard panel "p99 latency by route" to see which route.
2. `/oauth2/token` slow, `/v1/authorize` normal: JWKS fetch to the workload
   issuer is slow. Look for `cannot fetch signing keys` in logs and check
   egress to the issuer.
3. All routes slow: check PostgreSQL CPU and connections, then pod CPU
   throttling (`container_cpu_cfs_throttled_seconds_total`). Scale with the
   HPA ceiling if CPU-bound.

## Tracing a request

Every response carries `X-Correlation-ID`. Search logs and audit chains for
it: `jq 'select(.correlation_id=="<id>")' <pod>.jsonl`.
