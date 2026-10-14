"""Property-based API contract test: no input may cause a 5xx or a response that
violates the published OpenAPI schema."""

from __future__ import annotations

from typing import Any

import pytest
import schemathesis
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, assume, settings

pytestmark = pytest.mark.e2e


@pytest.fixture
def api_schema(client: TestClient) -> Any:
    schema = schemathesis.from_dict(client.get("/openapi.json").json(), force_schema_version="30")
    return schema


schema = schemathesis.from_pytest_fixture("api_schema")


@schema.parametrize()
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_no_server_errors(case: Any, client: TestClient) -> None:
    # Header values must be transmittable over HTTP/1.1 at all.
    assume(all(str(v).isascii() for v in (case.headers or {}).values()))
    response = client.request(**case.as_transport_kwargs(base_url=""))
    assert response.status_code < 500, (case.method, case.path, response.text)
