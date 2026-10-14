"""Fault injection: the fabric fails closed and reports unreadiness when dependencies break."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from identity_fabric.application.service import IdentityFabric
from identity_fabric.domain.errors import AttestationError, UnauthorizedError
from identity_fabric.infrastructure.database import make_engine
from identity_fabric.security.attestation import WorkloadAttestor
from identity_fabric.security.jwks import RemoteJwks
from tests.conftest import WORKLOAD_ISSUER, FakeIdp, registration, workload_token
from tests.unit.test_domain_and_security import make_agent

pytestmark = pytest.mark.chaos


def test_database_outage_flips_readiness(client: TestClient) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    assert client.get("/readyz").status_code == 200
    healthy = container.engine
    container.engine = make_engine("sqlite+aiosqlite:////nonexistent/dir/db.sqlite")
    try:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200  # liveness unaffected
    finally:
        container.engine = healthy


async def test_workload_issuer_outage_fails_closed(workload_idp: FakeIdp) -> None:
    def down(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(down)) as http:
        attestor = WorkloadAttestor({WORKLOAD_ISSUER: RemoteJwks("https://x/jwks", client=http)})
        with pytest.raises(AttestationError, match="cannot fetch"):
            await attestor.attest(make_agent(), workload_token(workload_idp))


async def test_jwks_timeout_fails_closed(workload_idp: FakeIdp) -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as http:
        with pytest.raises(UnauthorizedError):
            await RemoteJwks("https://x/jwks", client=http).key_for("k1")


async def test_audit_sink_failure_blocks_issuance(
    fabric: IdentityFabric, workload_idp: FakeIdp
) -> None:
    """If evidence cannot be written, the action must not complete silently."""
    await fabric.register(registration(), actor="admin")

    async def broken_append(_: object) -> None:
        raise OSError("disk full")

    fabric._audit._sink.append = broken_append  # type: ignore[method-assign]
    with pytest.raises(OSError, match="disk full"):
        await fabric.attest(
            "spiffe://agents.corp.test/agent/clinical/care-coordinator",
            workload_token(workload_idp),
        )
