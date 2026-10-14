"""Request and response bodies for the HTTP API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agentic_core.domain.classification import DataClassification
from pydantic import BaseModel, ConfigDict, Field

from identity_fabric.domain.models import Agent, AgentMandate, AgentStatus, WorkloadBinding


class AgentView(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent_id: str
    display_name: str
    status: AgentStatus
    scopes: list[str]
    risk: int
    max_classification: int
    mandate: AgentMandate
    workload: WorkloadBinding
    created_at: datetime
    updated_at: datetime
    attested_at: datetime | None
    status_reason: str | None

    @classmethod
    def of(cls, agent: Agent) -> AgentView:
        return cls(
            agent_id=agent.uri,
            display_name=agent.display_name,
            status=agent.status,
            scopes=sorted(agent.scopes),
            risk=int(agent.risk),
            max_classification=int(agent.max_classification),
            mandate=agent.mandate,
            workload=agent.workload,
            created_at=agent.created_at,
            updated_at=agent.updated_at,
            attested_at=agent.attested_at,
            status_reason=agent.status_reason,
        )


class AgentList(BaseModel):
    items: list[AgentView]
    limit: int
    offset: int


class AttestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workload_token: str = Field(min_length=20)


class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=5, max_length=500)


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=200)
    resource_type: str = Field(min_length=1, max_length=200)
    resource_id: str = Field(default="*", max_length=500)
    resource_classification: DataClassification = DataClassification.INTERNAL
    resource_attributes: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)


class OAuthError(BaseModel):
    error: str
    error_description: str
