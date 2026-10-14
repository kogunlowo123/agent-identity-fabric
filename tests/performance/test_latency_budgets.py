"""Latency budgets for hot paths. Loose enough for shared CI runners."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from identity_fabric.application.service import IdentityFabric
from identity_fabric.security.keys import KeyRing
from identity_fabric.security.tokens import TokenService
from tests.conftest import FakeIdp
from tests.unit.test_domain_and_security import make_agent
from tests.unit.test_fabric_service import activate, credential

pytestmark = pytest.mark.performance


def test_sign_and_verify_budget() -> None:
    service = TokenService(KeyRing.ephemeral(), issuer="https://i", audience="a")
    agent = make_agent()
    now = datetime.now(UTC)
    started = time.perf_counter()
    for _ in range(500):
        issued, _ = service.issue(agent, now=now)
        service.verify(issued.access_token, now=now)
    per_pair_ms = (time.perf_counter() - started) * 1000 / 500
    assert per_pair_ms < 5


async def test_full_validation_budget(fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
    await activate(fabric, workload_idp)
    token = await credential(fabric, workload_idp)
    started = time.perf_counter()
    for _ in range(200):
        await fabric.validate(token)
    per_call_ms = (time.perf_counter() - started) * 1000 / 200
    assert per_call_ms < 25
