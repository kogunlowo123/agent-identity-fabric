"""Full agent lifecycle over HTTP, exactly as a platform team and an agent would use it."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from identity_fabric.security.admin import AdminRole
from tests.conftest import FakeIdp, admin_headers, agent_uri, registration, workload_token

pytestmark = pytest.mark.e2e

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TYPE = "urn:ietf:params:oauth:token-type:jwt"


def register(client: TestClient, admin_idp: FakeIdp, name: str, **kw: object) -> None:
    response = client.post(
        "/v1/agents",
        json=registration(name, **kw).model_dump(mode="json"),  # type: ignore[arg-type]
        headers=admin_headers(admin_idp, AdminRole.REGISTRAR),
    )
    assert response.status_code == 201, response.text


def attest_and_token(client: TestClient, idp: FakeIdp, name: str) -> str:
    attested = client.post(
        "/v1/attest",
        params={"agent_uri": agent_uri(name)},
        json={"workload_token": workload_token(idp, name)},
    )
    assert attested.json()["status"] == "active"
    issued = client.post(
        "/oauth2/token",
        data={
            "grant_type": JWT_BEARER,
            "client_id": agent_uri(name),
            "assertion": workload_token(idp, name),
        },
    )
    assert issued.status_code == 200, issued.text
    assert issued.headers["cache-control"] == "no-store"
    return str(issued.json()["access_token"])


def test_full_lifecycle(client: TestClient, admin_idp: FakeIdp, workload_idp: FakeIdp) -> None:
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["token_endpoint"] == "https://identity.corp.test/oauth2/token"
    assert client.get("/.well-known/jwks.json").json()["keys"][0]["alg"] == "EdDSA"

    register(client, admin_idp, "orchestrator")
    register(client, admin_idp, "scheduler", scopes=frozenset({"scheduling:read", "fhir:read:*"}))
    orchestrator = attest_and_token(client, workload_idp, "orchestrator")
    scheduler = attest_and_token(client, workload_idp, "scheduler")

    inventory = client.get("/v1/agents", headers=admin_headers(admin_idp, AdminRole.AUDITOR))
    assert {a["agent_id"] for a in inventory.json()["items"]} == {
        agent_uri("orchestrator"),
        agent_uri("scheduler"),
    }
    one = client.get(
        f"/v1/agents/{agent_uri('scheduler')}", headers=admin_headers(admin_idp, AdminRole.AUDITOR)
    )
    assert one.json()["mandate"]["escalation_contact"] == "care-ops-oncall"

    exchanged = client.post(
        "/oauth2/token",
        data={
            "grant_type": EXCHANGE,
            "subject_token": orchestrator,
            "subject_token_type": JWT_TYPE,
            "actor_token": scheduler,
            "actor_token_type": JWT_TYPE,
            "scope": "scheduling:read",
        },
    )
    assert exchanged.status_code == 200, exchanged.text
    delegated = exchanged.json()["access_token"]

    introspected = client.post("/oauth2/introspect", data={"token": delegated}).json()
    assert introspected["active"] is True
    assert introspected["act"] == {"sub": agent_uri("scheduler")}

    decision = client.post(
        "/v1/authorize",
        json={"action": "scheduling:read", "resource_type": "schedule", "resource_id": "s1"},
        headers={"Authorization": f"Bearer {delegated}"},
    )
    assert decision.json()["decision"] == "allow"
    assert decision.json()["delegation_chain"] == [agent_uri("scheduler")]

    revoked = client.post(
        "/oauth2/revoke",
        data={"token": delegated},
        headers={"Authorization": f"Bearer {orchestrator}"},
    )
    assert revoked.status_code == 200
    assert client.post("/oauth2/introspect", data={"token": delegated}).json() == {"active": False}

    security = admin_headers(admin_idp, AdminRole.SECURITY)
    reason = {"reason": "credential exposure investigation"}
    q = {"agent_uri": agent_uri("orchestrator")}
    assert client.post("/v1/suspend", params=q, json=reason, headers=security).json()["status"] == (
        "suspended"
    )
    assert not client.post("/oauth2/introspect", data={"token": orchestrator}).json()["active"]
    assert client.post("/v1/reinstate", params=q, json=reason, headers=security).status_code == 200
    assert (
        client.post("/v1/revoke-agent", params=q, json=reason, headers=security).json()["status"]
        == "revoked"
    )
    blocked = client.post(
        "/oauth2/token",
        data={
            "grant_type": JWT_BEARER,
            "client_id": agent_uri("orchestrator"),
            "assertion": workload_token(workload_idp, "orchestrator"),
        },
    )
    assert blocked.status_code == 400
    assert blocked.json()["error"] == "invalid_grant"

    metrics = client.get("/metrics").text
    assert 'fabric_tokens_issued_total{grant="jwt-bearer"} 2.0' in metrics
    assert 'fabric_authorization_decisions_total{decision="allow"} 1.0' in metrics
    assert "fabric_http_request_duration_seconds" in metrics


def test_operational_endpoints(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    response = client.get("/healthz", headers={"X-Correlation-ID": "trace-123"})
    assert response.headers["x-correlation-id"] == "trace-123"
    assert response.headers["x-content-type-options"] == "nosniff"
    generated = client.get("/healthz", headers={"X-Correlation-ID": "x" * 200})
    assert generated.headers["x-correlation-id"] != "x" * 200


def test_admin_authorization(client: TestClient, admin_idp: FakeIdp) -> None:
    body = registration().model_dump(mode="json")
    assert client.post("/v1/agents", json=body).status_code == 401
    forbidden = client.post(
        "/v1/agents", json=body, headers=admin_headers(admin_idp, AdminRole.AUDITOR)
    )
    assert forbidden.status_code == 403
    impostor = FakeIdp(admin_idp.issuer, kid=admin_idp.kid)
    spoofed = client.post(
        "/v1/agents", json=body, headers=admin_headers(impostor, AdminRole.REGISTRAR)
    )
    assert spoofed.status_code == 401
    assert spoofed.headers["www-authenticate"] == "Bearer"


def test_oauth_errors(client: TestClient, admin_idp: FakeIdp, workload_idp: FakeIdp) -> None:
    assert client.post("/oauth2/token", data={"grant_type": "password"}).json()["error"] == (
        "fabric_error"
    )
    assert client.post("/oauth2/token", data={"grant_type": JWT_BEARER}).json()["error"] == (
        "invalid_grant"
    )
    assert client.post("/oauth2/token", data={"grant_type": EXCHANGE}).json()["error"] == (
        "invalid_grant"
    )
    wrong_type = client.post(
        "/oauth2/token",
        data={
            "grant_type": EXCHANGE,
            "subject_token": "a",
            "actor_token": "b",
            "subject_token_type": "urn:ietf:params:oauth:token-type:saml2",
            "actor_token_type": JWT_TYPE,
        },
    )
    assert wrong_type.json()["error_description"] == "unsupported token type"
    bogus = client.post(
        "/oauth2/token",
        data={
            "grant_type": EXCHANGE,
            "subject_token": "a.b.c",
            "actor_token": "a.b.c",
            "subject_token_type": JWT_TYPE,
            "actor_token_type": JWT_TYPE,
        },
    )
    assert bogus.json()["error"] == "invalid_grant"
    assert client.post("/v1/authorize", json={"action": "x", "resource_type": "y"}).status_code == (
        401
    )
    invalid = client.post(
        "/v1/agents", json={"namespace": "x"}, headers=admin_headers(admin_idp, AdminRole.REGISTRAR)
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"] == "invalid_request"
    missing = client.get(
        f"/v1/agents/{agent_uri('ghost')}", headers=admin_headers(admin_idp, AdminRole.AUDITOR)
    )
    assert missing.status_code == 404
