"""Agent registration, lifecycle and credential models."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum

from agentic_core.domain.classification import DataClassification, RiskLevel
from agentic_core.domain.identifiers import AgentId
from pydantic import BaseModel, ConfigDict, Field, field_validator

from identity_fabric.domain.errors import InvalidStateError

SCOPE_PATTERN = re.compile(r"^[a-z][a-z0-9_.\-]*(:[a-z0-9_.\-*]+)+$")


class AgentStatus(StrEnum):
    PENDING = "pending"  # registered, not yet attested
    ACTIVE = "active"  # attested, may obtain credentials
    SUSPENDED = "suspended"  # temporarily blocked, can be reinstated
    REVOKED = "revoked"  # terminal


_TRANSITIONS: dict[AgentStatus, frozenset[AgentStatus]] = {
    AgentStatus.PENDING: frozenset({AgentStatus.ACTIVE, AgentStatus.REVOKED}),
    AgentStatus.ACTIVE: frozenset({AgentStatus.SUSPENDED, AgentStatus.REVOKED}),
    AgentStatus.SUSPENDED: frozenset({AgentStatus.ACTIVE, AgentStatus.REVOKED}),
    AgentStatus.REVOKED: frozenset(),
}


def validate_scopes(scopes: frozenset[str]) -> frozenset[str]:
    bad = sorted(s for s in scopes if not SCOPE_PATTERN.fullmatch(s))
    if bad:
        raise ValueError(f"invalid scopes {bad}; expected resource:action[:qualifier]")
    return scopes


class WorkloadBinding(BaseModel):
    """Which runtime workload may claim this agent identity."""

    model_config = ConfigDict(frozen=True)

    issuer: str = Field(description="Workload token issuer, e.g. the cluster OIDC issuer URL")
    subject: str = Field(description="e.g. system:serviceaccount:<namespace>:<name>")
    audience: str = Field(description="Audience the projected token must carry")
    image_digests: frozenset[str] = Field(
        default=frozenset(), description="Allowed sha256 image digests; empty disables the check"
    )

    @field_validator("image_digests")
    @classmethod
    def _digests(cls, value: frozenset[str]) -> frozenset[str]:
        bad = [d for d in value if not re.fullmatch(r"sha256:[0-9a-f]{64}", d)]
        if bad:
            raise ValueError(f"invalid image digests: {bad}")
        return value


class AgentMandate(BaseModel):
    """Role, mission and operating boundaries recorded at registration."""

    model_config = ConfigDict(frozen=True)

    mission: str = Field(min_length=10, max_length=2000)
    business_owner: str = Field(min_length=3)
    technical_owner: str = Field(min_length=3)
    protected_resources: tuple[str, ...] = ()
    disallowed_actions: tuple[str, ...] = ()
    escalation_contact: str = Field(min_length=3)


class Agent(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent_id: AgentId
    display_name: str = Field(min_length=3, max_length=120)
    mandate: AgentMandate
    scopes: frozenset[str]
    risk: RiskLevel
    max_classification: DataClassification
    workload: WorkloadBinding
    status: AgentStatus = AgentStatus.PENDING
    created_at: datetime
    updated_at: datetime
    attested_at: datetime | None = None
    status_reason: str | None = None
    credential_epoch: int = Field(
        default=0, description="Incremented on suspension/revocation to invalidate issued tokens"
    )

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, value: frozenset[str]) -> frozenset[str]:
        return validate_scopes(value)

    @property
    def uri(self) -> str:
        return self.agent_id.uri

    def transition(self, target: AgentStatus, *, at: datetime, reason: str | None) -> Agent:
        if target not in _TRANSITIONS[self.status]:
            raise InvalidStateError(f"cannot move agent {self.uri} from {self.status} to {target}")
        update: dict[str, object] = {"status": target, "updated_at": at, "status_reason": reason}
        if target is AgentStatus.ACTIVE and self.status is AgentStatus.PENDING:
            update["attested_at"] = at
        if target in {AgentStatus.SUSPENDED, AgentStatus.REVOKED}:
            update["credential_epoch"] = self.credential_epoch + 1
        return self.model_copy(update=update)


class Actor(BaseModel):
    """One link in a delegation chain (RFC 8693 ``act`` claim)."""

    model_config = ConfigDict(frozen=True)

    sub: str
    act: Actor | None = None

    def depth(self) -> int:
        return 1 + (self.act.depth() if self.act else 0)

    def subjects(self) -> list[str]:
        return [self.sub, *(self.act.subjects() if self.act else [])]


class IssuedToken(BaseModel):
    model_config = ConfigDict(frozen=True)

    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - RFC 6750 token type
    expires_in: int
    scope: str
    issued_token_type: str = "urn:ietf:params:oauth:token-type:jwt"  # noqa: S105 - URN


class TokenClaims(BaseModel):
    """Verified claims of a fabric-issued agent credential."""

    model_config = ConfigDict(frozen=True)

    iss: str
    sub: str
    aud: str
    jti: str
    iat: int
    exp: int
    scope: str
    risk: int
    max_cls: int
    epoch: int
    act: Actor | None = None

    @property
    def scopes(self) -> frozenset[str]:
        return frozenset(self.scope.split())

    @property
    def delegation_depth(self) -> int:
        return self.act.depth() if self.act else 0
