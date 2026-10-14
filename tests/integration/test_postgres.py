"""Repository behaviour against a real PostgreSQL (CI service container).

Runs when FABRIC_TEST_DATABASE_URL points at PostgreSQL, e.g.
postgresql+asyncpg://fabric:fabric@localhost:5432/fabric
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from identity_fabric.domain.models import AgentStatus
from identity_fabric.infrastructure.database import (
    SqlAgentRepository,
    SqlRevocationStore,
    create_schema,
    make_engine,
)
from tests.unit.test_domain_and_security import make_agent

URL = os.environ.get("FABRIC_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL.startswith("postgresql"), reason="PostgreSQL not configured"),
]


async def test_repository_round_trip() -> None:
    engine = make_engine(URL)
    await create_schema(engine)
    await create_schema(engine)  # idempotent
    repo = SqlAgentRepository(engine)
    store = SqlRevocationStore(engine)
    agent = make_agent(name=f"pg-{datetime.now(UTC).timestamp():.0f}")
    await repo.add(agent)
    assert (await repo.get(agent.uri)) == agent
    active = agent.transition(AgentStatus.ACTIVE, at=datetime.now(UTC), reason="t")
    await repo.update(active)
    assert any(a.uri == agent.uri for a in await repo.list(status=AgentStatus.ACTIVE))

    past = datetime.now(UTC) - timedelta(hours=1)
    await store.revoke("jti-pg-1", past)
    assert await store.is_revoked("jti-pg-1")
    assert await store.purge_expired(datetime.now(UTC)) >= 1
    await engine.dispose()
