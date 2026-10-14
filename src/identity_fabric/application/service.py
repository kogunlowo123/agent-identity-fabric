"""Identity fabric use cases.

Lifecycle: register -> attest -> (credentials, delegation, authorization)
-> suspend/reinstate -> revoke. Every state change and every credential is
recorded in the signed audit chain.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence
from typing import Any

from agentic_core.audit import AuditLog
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.domain.identifiers import AgentId
from agentic_core.observability import correlation_id
from agentic_core.policy import PolicyDecision, PolicyEngine, PolicyRequest, Resource, Subject
from pydantic import BaseModel, ConfigDict, Field

from identity_fabric.domain.errors import (
    InvalidGrantError,
    InvalidStateError,
    NotFoundError,
    UnauthorizedError,
)
from identity_fabric.domain.models import (
    Actor,
    Agent,
    AgentMandate,
    AgentStatus,
    IssuedToken,
    TokenClaims,
    WorkloadBinding,
    validate_scopes,
)
from identity_fabric.domain.ports import AgentRepository, Clock, RevocationStore
from identity_fabric.security.attestation import WorkloadAttestor
from identity_fabric.security.tokens import TokenService


class RegisterAgent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    namespace: str
    name: str
    display_name: str = Field(min_length=3, max_length=120)
    mandate: AgentMandate
    scopes: frozenset[str] = Field(min_length=1)
    risk: RiskLevel
    max_classification: DataClassification
    workload: WorkloadBinding


class Introspection(BaseModel):
    """RFC 7662 response. Inactive tokens carry only ``active: false``."""

    model_config = ConfigDict(frozen=True)

    active: bool
    sub: str | None = None
    scope: str | None = None
    exp: int | None = None
    iat: int | None = None
    jti: str | None = None
    iss: str | None = None
    aud: str | None = None
    act: dict[str, Any] | None = None
    agent_status: str | None = None


class AuthorizationDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    agent: str
    action: str
    resource: str
    matched_rules: tuple[str, ...]
    policy_version: str
    policy_digest: str
    reason: str
    delegation_chain: tuple[str, ...]


class IdentityFabric:
    def __init__(
        self,
        *,
        trust_domain: str,
        agents: AgentRepository,
        revocations: RevocationStore,
        tokens: TokenService,
        attestor: WorkloadAttestor,
        policy: PolicyEngine,
        audit: AuditLog,
        clock: Clock,
    ) -> None:
        self._trust_domain = trust_domain
        self._agents = agents
        self._revocations = revocations
        self._tokens = tokens
        self._attestor = attestor
        self._policy = policy
        self._audit = audit
        self._clock = clock

    @property
    def tokens(self) -> TokenService:
        return self._tokens

    # ------------------------------------------------------------------ lifecycle

    async def register(self, command: RegisterAgent, *, actor: str) -> Agent:
        if not self._attestor.trusts(command.workload.issuer):
            raise InvalidStateError(f"workload issuer {command.workload.issuer} is not trusted")
        now = self._clock.now()
        agent = Agent(
            agent_id=AgentId(
                trust_domain=self._trust_domain, namespace=command.namespace, name=command.name
            ),
            display_name=command.display_name,
            mandate=command.mandate,
            scopes=command.scopes,
            risk=command.risk,
            max_classification=command.max_classification,
            workload=command.workload,
            created_at=now,
            updated_at=now,
        )
        await self._agents.add(agent)
        await self._record(
            actor,
            "agent.register",
            agent.uri,
            "success",
            {"scopes": sorted(agent.scopes), "risk": int(agent.risk)},
        )
        return agent

    async def get(self, uri: str) -> Agent:
        agent = await self._agents.get(uri)
        if agent is None:
            raise NotFoundError(f"agent {uri} not found")
        return agent

    async def list(self, *, status: AgentStatus | None, limit: int, offset: int) -> Sequence[Agent]:
        return await self._agents.list(status=status, limit=limit, offset=offset)

    async def attest(self, uri: str, workload_token: str) -> Agent:
        agent = await self.get(uri)
        if agent.status is not AgentStatus.PENDING:
            raise InvalidStateError(f"agent {uri} is {agent.status}, not pending")
        try:
            result = await self._attestor.attest(agent, workload_token)
        except Exception:
            await self._record(uri, "agent.attest", uri, "failure", {})
            raise
        updated = agent.transition(AgentStatus.ACTIVE, at=self._clock.now(), reason="attested")
        await self._agents.update(updated)
        await self._record(
            uri,
            "agent.attest",
            uri,
            "success",
            {"workload_subject": result.subject, "image_digest": result.image_digest},
        )
        return updated

    async def set_status(self, uri: str, target: AgentStatus, *, actor: str, reason: str) -> Agent:
        agent = await self.get(uri)
        if target is AgentStatus.ACTIVE and agent.status is AgentStatus.PENDING:
            raise InvalidStateError("pending agents become active only through attestation")
        updated = agent.transition(target, at=self._clock.now(), reason=reason)
        await self._agents.update(updated)
        await self._record(actor, f"agent.{target.value}", uri, "success", {"reason": reason})
        return updated

    # ---------------------------------------------------------------- credentials

    async def issue_for_workload(
        self, uri: str, workload_token: str, *, scopes: frozenset[str] | None
    ) -> IssuedToken:
        """RFC 7523 jwt-bearer grant: workload token in, short-lived agent credential out."""
        agent = await self.get(uri)
        if agent.status is not AgentStatus.ACTIVE:
            await self._record(uri, "token.issue", uri, "denied", {"status": agent.status.value})
            raise InvalidGrantError(f"agent {uri} is {agent.status}")
        try:
            await self._attestor.attest(agent, workload_token)
        except Exception as exc:
            await self._record(uri, "token.issue", uri, "denied", {"reason": "attestation"})
            raise InvalidGrantError("workload attestation failed") from exc
        if scopes is not None:
            validate_scopes(scopes)
        issued, claims = self._tokens.issue(agent, now=self._clock.now(), requested_scopes=scopes)
        await self._record(
            uri,
            "token.issue",
            uri,
            "success",
            {"jti": claims.jti, "scope": claims.scope, "exp": claims.exp},
        )
        return issued

    async def exchange(
        self, subject_token: str, actor_token: str, *, scopes: frozenset[str] | None
    ) -> IssuedToken:
        """RFC 8693 delegation.

        The *actor* (the agent presenting ``actor_token``) receives a credential
        to act for the *subject*. Scopes are the intersection of what the
        subject holds and what the actor is registered for, further narrowed
        by the request. The result can never outlive the subject token.
        """
        subject_claims = await self.validate(subject_token)
        actor_claims = await self.validate(actor_token)
        actor_agent = await self.get(actor_claims.sub)
        if actor_claims.sub == subject_claims.sub:
            raise InvalidGrantError("an agent cannot delegate to itself")
        if actor_claims.sub in (subject_claims.act.subjects() if subject_claims.act else []):
            raise InvalidGrantError("delegation cycle detected")

        allowed = subject_claims.scopes & actor_agent.scopes
        requested = allowed if scopes is None else scopes
        if scopes is not None:
            validate_scopes(scopes)
        if not requested <= allowed:
            await self._record(
                actor_claims.sub,
                "token.exchange",
                subject_claims.sub,
                "denied",
                {"requested": sorted(requested), "allowed": sorted(allowed)},
            )
            raise InvalidGrantError(
                f"requested scopes exceed delegable set: {sorted(requested - allowed)}"
            )

        chain = Actor(sub=actor_claims.sub, act=subject_claims.act)
        subject_agent = await self.get(subject_claims.sub)
        # Issue under the subject's identity but bounded by the actor's ceilings.
        bounded = subject_agent.model_copy(
            update={
                "risk": max(subject_agent.risk, actor_agent.risk),
                "max_classification": min(
                    subject_agent.max_classification, actor_agent.max_classification
                ),
            }
        )
        issued, claims = self._tokens.issue(
            bounded,
            now=self._clock.now(),
            requested_scopes=requested,
            actor=chain,
            not_after=TokenService.expiry(subject_claims),
        )
        await self._record(
            actor_claims.sub,
            "token.exchange",
            subject_claims.sub,
            "success",
            {"jti": claims.jti, "scope": claims.scope, "depth": chain.depth()},
        )
        return issued

    async def validate(self, token: str) -> TokenClaims:
        """Full validation: signature, expiry, revocation, and every agent in the chain."""
        now = self._clock.now()
        claims = self._tokens.verify(token, now=now)
        if await self._revocations.is_revoked(claims.jti):
            raise UnauthorizedError("token has been revoked")
        agent = await self._agents.get(claims.sub)
        if agent is None or agent.status is not AgentStatus.ACTIVE:
            raise UnauthorizedError("subject agent is not active")
        if claims.epoch != agent.credential_epoch:
            raise UnauthorizedError("token predates a suspension or revocation")
        for sub in claims.act.subjects() if claims.act else []:
            delegate = await self._agents.get(sub)
            if delegate is None or delegate.status is not AgentStatus.ACTIVE:
                raise UnauthorizedError(f"delegate {sub} is not active")
        return claims

    async def introspect(self, token: str) -> Introspection:
        try:
            claims = await self.validate(token)
        except UnauthorizedError:
            return Introspection(active=False)
        return Introspection(
            active=True,
            sub=claims.sub,
            scope=claims.scope,
            exp=claims.exp,
            iat=claims.iat,
            jti=claims.jti,
            iss=claims.iss,
            aud=claims.aud,
            act=claims.act.model_dump(exclude_none=True) if claims.act else None,
            agent_status=AgentStatus.ACTIVE.value,
        )

    async def revoke_token(self, token: str, *, actor: str) -> None:
        """RFC 7009: revoking an invalid or unknown token is not an error."""
        try:
            claims = self._tokens.verify(token)
        except UnauthorizedError:
            return
        await self._revocations.revoke(claims.jti, TokenService.expiry(claims))
        await self._record(actor, "token.revoke", claims.sub, "success", {"jti": claims.jti})

    async def purge_revocations(self) -> int:
        return await self._revocations.purge_expired(self._clock.now())

    # --------------------------------------------------------------- authorization

    async def authorize(
        self, token: str, *, action: str, resource: Resource, environment: dict[str, Any]
    ) -> AuthorizationDecision:
        claims = await self.validate(token)
        subject = Subject(
            id=claims.sub,
            kind="agent",
            attributes={
                "status": AgentStatus.ACTIVE.value,
                "scopes": sorted(claims.scopes),
                "risk": claims.risk,
                "max_classification": claims.max_cls,
                "delegation_depth": claims.delegation_depth,
                "delegated": claims.act is not None,
                "action_in_scope": any(
                    fnmatch.fnmatchcase(action, scope) for scope in claims.scopes
                ),
            },
        )
        decision: PolicyDecision = self._policy.evaluate(
            PolicyRequest(
                subject=subject,
                action=action,
                resource=resource,
                risk=RiskLevel(max(1, min(4, claims.risk))),
                environment=environment,
            )
        )
        # Classification ceiling is enforced regardless of policy content.
        if resource.classification > claims.max_cls and decision.decision is not Decision.DENY:
            decision = decision.model_copy(
                update={
                    "decision": Decision.DENY,
                    "reason": "resource exceeds agent classification",
                    "matched_rules": (),
                }
            )
        chain = tuple(claims.act.subjects()) if claims.act else ()
        await self._record(
            claims.sub,
            action,
            f"{resource.type}:{resource.id}",
            decision.decision.value,
            {
                "jti": claims.jti,
                "rules": list(decision.matched_rules),
                "policy_digest": decision.policy_digest,
                "chain": list(chain),
            },
        )
        return AuthorizationDecision(
            decision=decision.decision,
            agent=claims.sub,
            action=action,
            resource=f"{resource.type}:{resource.id}",
            matched_rules=decision.matched_rules,
            policy_version=decision.policy_version,
            policy_digest=decision.policy_digest,
            reason=decision.reason,
            delegation_chain=chain,
        )

    # ---------------------------------------------------------------------- audit

    async def _record(
        self, actor: str, action: str, resource: str, outcome: str, details: dict[str, Any]
    ) -> None:
        await self._audit.record(
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            correlation_id=correlation_id(),
            details=details,
        )
