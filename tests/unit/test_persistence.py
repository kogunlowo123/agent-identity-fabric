from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from identity_fabric.domain.errors import ConflictError, NotFoundError
from identity_fabric.domain.models import AgentStatus
from identity_fabric.infrastructure.database import (
    SqlAgentRepository,
    SqlRevocationStore,
    SystemClock,
    create_schema,
    make_engine,
)
from tests.unit.test_domain_and_security import make_agent


async def test_sql_repository(tmp_path: Path) -> None:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'r.db'}")
    await create_schema(engine)
    await create_schema(engine)
    repo = SqlAgentRepository(engine)
    agent = make_agent()
    await repo.add(agent)
    with pytest.raises(ConflictError):
        await repo.add(agent)
    assert await repo.get(agent.uri) == agent
    assert await repo.get("spiffe://x/agent/a/b") is None
    with pytest.raises(NotFoundError):
        await repo.update(make_agent(name="ghost"))
    for i in range(3):
        await repo.add(make_agent(name=f"bulk-{i}"))
    page = await repo.list(limit=2, offset=1)
    assert len(page) == 2
    assert await repo.list(status=AgentStatus.ACTIVE) == []
    await engine.dispose()


async def test_revocation_store(tmp_path: Path) -> None:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'v.db'}")
    await create_schema(engine)
    store = SqlRevocationStore(engine)
    now = datetime.now(UTC)
    await store.revoke("a", now - timedelta(minutes=1))
    await store.revoke("b", now + timedelta(minutes=10))
    await store.revoke("b", now + timedelta(minutes=10))
    assert await store.is_revoked("a")
    assert not await store.is_revoked("z")
    assert await store.purge_expired(now) == 1
    assert not await store.is_revoked("a")
    assert await store.is_revoked("b")
    await engine.dispose()


def test_system_clock_is_utc() -> None:
    assert SystemClock().now().tzinfo is UTC
