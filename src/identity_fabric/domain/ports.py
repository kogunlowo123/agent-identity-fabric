"""Ports the application layer depends on. Adapters live in infrastructure."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from identity_fabric.domain.models import Agent, AgentStatus


class AgentRepository(Protocol):
    async def add(self, agent: Agent) -> None: ...

    async def get(self, uri: str) -> Agent | None: ...

    async def update(self, agent: Agent) -> None: ...

    async def list(
        self, *, status: AgentStatus | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[Agent]: ...


class RevocationStore(Protocol):
    async def revoke(self, jti: str, expires_at: datetime) -> None: ...

    async def is_revoked(self, jti: str) -> bool: ...

    async def purge_expired(self, now: datetime) -> int: ...


class Clock(Protocol):
    def now(self) -> datetime: ...
