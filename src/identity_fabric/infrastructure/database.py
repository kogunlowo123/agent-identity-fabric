"""SQLAlchemy Core persistence. PostgreSQL in production; any async dialect works."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from identity_fabric.domain.errors import ConflictError, NotFoundError
from identity_fabric.domain.models import Agent, AgentStatus

metadata = MetaData()

agents = Table(
    "agents",
    metadata,
    Column("uri", String(512), primary_key=True),
    Column("status", String(16), nullable=False),
    Column("document", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Index("ix_agents_status", "status"),
)

revoked_tokens = Table(
    "revoked_tokens",
    metadata,
    Column("jti", String(64), primary_key=True),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Index("ix_revoked_expires", "expires_at"),
)

schema_version = Table(
    "schema_version",
    metadata,
    Column("version", Integer, primary_key=True),
)

SCHEMA_VERSION = 1


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        current = (await conn.execute(select(schema_version.c.version))).scalar()
        if current is None:
            await conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class SqlAgentRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, agent: Agent) -> None:
        async with self._engine.begin() as conn:
            exists = (
                await conn.execute(select(agents.c.uri).where(agents.c.uri == agent.uri))
            ).first()
            if exists:
                raise ConflictError(f"agent {agent.uri} already registered")
            await conn.execute(
                insert(agents).values(
                    uri=agent.uri,
                    status=agent.status.value,
                    document=agent.model_dump_json(),
                    created_at=agent.created_at,
                    updated_at=agent.updated_at,
                )
            )

    async def get(self, uri: str) -> Agent | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(select(agents.c.document).where(agents.c.uri == uri))).first()
        return Agent.model_validate_json(row[0]) if row else None

    async def update(self, agent: Agent) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(agents)
                .where(agents.c.uri == agent.uri)
                .values(
                    status=agent.status.value,
                    document=agent.model_dump_json(),
                    updated_at=agent.updated_at,
                )
            )
            if result.rowcount == 0:
                raise NotFoundError(f"agent {agent.uri} not found")

    async def list(
        self, *, status: AgentStatus | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[Agent]:
        query = select(agents.c.document).order_by(agents.c.uri).limit(limit).offset(offset)
        if status is not None:
            query = query.where(agents.c.status == status.value)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [Agent.model_validate_json(r[0]) for r in rows]


class SqlRevocationStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def revoke(self, jti: str, expires_at: datetime) -> None:
        async with self._engine.begin() as conn:
            exists = (
                await conn.execute(select(revoked_tokens.c.jti).where(revoked_tokens.c.jti == jti))
            ).first()
            if not exists:
                await conn.execute(insert(revoked_tokens).values(jti=jti, expires_at=expires_at))

    async def is_revoked(self, jti: str) -> bool:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(revoked_tokens.c.jti).where(revoked_tokens.c.jti == jti))
            ).first()
        return row is not None

    async def purge_expired(self, now: datetime) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                delete(revoked_tokens).where(revoked_tokens.c.expires_at < _aware(now))
            )
        return int(result.rowcount or 0)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
