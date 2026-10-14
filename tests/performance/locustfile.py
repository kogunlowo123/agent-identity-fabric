"""Load profile for a deployed fabric.

Run against a staging deployment, never production:

    FABRIC_LOAD_AGENT_TOKEN=<agent credential> \
    locust -f tests/performance/locustfile.py --host https://identity.staging.example \
           --users 200 --spawn-rate 20 --run-time 10m --headless

Agents validate and authorize far more often than they obtain credentials,
so the mix weights introspection and authorization over issuance.
"""

from __future__ import annotations

import os

from locust import HttpUser, between, task

TOKEN = os.environ.get("FABRIC_LOAD_AGENT_TOKEN", "")


class AgentTraffic(HttpUser):
    wait_time = between(0.05, 0.25)

    @task(10)
    def authorize(self) -> None:
        self.client.post(
            "/v1/authorize",
            json={"action": "scheduling:read", "resource_type": "schedule", "resource_id": "s1"},
            headers={"Authorization": f"Bearer {TOKEN}"},
            name="/v1/authorize",
        )

    @task(5)
    def introspect(self) -> None:
        self.client.post("/oauth2/introspect", data={"token": TOKEN}, name="/oauth2/introspect")

    @task(1)
    def jwks(self) -> None:
        self.client.get("/.well-known/jwks.json", name="/.well-known/jwks.json")
