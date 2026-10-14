"""Service metrics exposed on /metrics in Prometheus text format."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class FabricMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.requests = Histogram(
            "fabric_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
        )
        self.tokens_issued = Counter(
            "fabric_tokens_issued_total",
            "Agent credentials issued",
            ["grant"],
            registry=self.registry,
        )
        self.token_failures = Counter(
            "fabric_token_failures_total",
            "Rejected token requests",
            ["grant", "error"],
            registry=self.registry,
        )
        self.authz_decisions = Counter(
            "fabric_authorization_decisions_total",
            "Authorization decisions",
            ["decision"],
            registry=self.registry,
        )
        self.lifecycle = Counter(
            "fabric_agent_lifecycle_events_total",
            "Agent lifecycle transitions",
            ["event"],
            registry=self.registry,
        )
        self.revocations_purged = Gauge(
            "fabric_revocations_purged_last",
            "Expired revocations removed in the last sweep",
            registry=self.registry,
        )
