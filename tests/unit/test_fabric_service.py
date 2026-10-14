from __future__ import annotations

import pytest
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.policy import Resource

from identity_fabric.application.service import IdentityFabric
from identity_fabric.domain.errors import (
    ConflictError,
    InvalidGrantError,
    InvalidStateError,
    NotFoundError,
    UnauthorizedError,
)
from identity_fabric.domain.models import AgentStatus
from identity_fabric.runtime.container import Container
from tests.conftest import FakeClock, FakeIdp, agent_uri, registration, workload_token


async def activate(
    fabric: IdentityFabric, idp: FakeIdp, name: str = "care-coordinator", **kw: object
) -> None:
    await fabric.register(registration(name, **kw), actor="admin")  # type: ignore[arg-type]
    await fabric.attest(agent_uri(name), workload_token(idp, name))


async def credential(
    fabric: IdentityFabric,
    idp: FakeIdp,
    name: str = "care-coordinator",
    scopes: frozenset[str] | None = None,
) -> str:
    issued = await fabric.issue_for_workload(
        agent_uri(name), workload_token(idp, name), scopes=scopes
    )
    return issued.access_token


class TestLifecycle:
    async def test_register_attest_list(
        self, fabric: IdentityFabric, workload_idp: FakeIdp
    ) -> None:
        agent = await fabric.register(registration(), actor="admin")
        assert agent.status is AgentStatus.PENDING
        with pytest.raises(ConflictError):
            await fabric.register(registration(), actor="admin")
        active = await fabric.attest(agent.uri, workload_token(workload_idp))
        assert active.status is AgentStatus.ACTIVE
        with pytest.raises(InvalidStateError, match="not pending"):
            await fabric.attest(agent.uri, workload_token(workload_idp))
        assert [
            a.uri for a in await fabric.list(status=AgentStatus.ACTIVE, limit=10, offset=0)
        ] == [agent.uri]
        assert await fabric.list(status=AgentStatus.REVOKED, limit=10, offset=0) == []

    async def test_untrusted_issuer_rejected_at_registration(self, fabric: IdentityFabric) -> None:
        reg = registration()
        bad = reg.model_copy(
            update={"workload": reg.workload.model_copy(update={"issuer": "https://evil"})}
        )
        with pytest.raises(InvalidStateError, match="not trusted"):
            await fabric.register(bad, actor="admin")

    async def test_failed_attestation_is_audited(
        self, container: Container, workload_idp: FakeIdp
    ) -> None:
        await container.fabric.register(registration(), actor="admin")
        with pytest.raises(Exception, match="subject"):
            await container.fabric.attest(agent_uri(), workload_token(workload_idp, "other"))
        events = [e async for e in container.fabric._audit._sink.read()]
        assert [e.action for e in events][-1] == "agent.attest"
        assert events[-1].outcome == "failure"

    async def test_status_changes(self, fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
        await fabric.register(registration(), actor="admin")
        with pytest.raises(InvalidStateError, match="only through attestation"):
            await fabric.set_status(agent_uri(), AgentStatus.ACTIVE, actor="sec", reason="x")
        await fabric.attest(agent_uri(), workload_token(workload_idp))
        suspended = await fabric.set_status(
            agent_uri(), AgentStatus.SUSPENDED, actor="sec", reason="incident"
        )
        assert suspended.status_reason == "incident"
        with pytest.raises(NotFoundError):
            await fabric.get(agent_uri("missing"))


class TestCredentials:
    async def test_issue_and_validate(self, fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
        await activate(fabric, workload_idp)
        token = await credential(fabric, workload_idp, scopes=frozenset({"scheduling:read"}))
        claims = await fabric.validate(token)
        assert claims.sub == agent_uri()
        assert claims.scopes == {"scheduling:read"}
        introspection = await fabric.introspect(token)
        assert introspection.active
        assert introspection.scope == "scheduling:read"

    async def test_inactive_agent_cannot_obtain_credentials(
        self, fabric: IdentityFabric, workload_idp: FakeIdp
    ) -> None:
        await fabric.register(registration(), actor="admin")
        with pytest.raises(InvalidGrantError, match="pending"):
            await credential(fabric, workload_idp)

    async def test_bad_workload_token(self, fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
        await activate(fabric, workload_idp)
        with pytest.raises(InvalidGrantError, match="attestation"):
            await fabric.issue_for_workload(
                agent_uri(), workload_token(workload_idp, "intruder"), scopes=None
            )

    async def test_suspension_invalidates_outstanding_tokens(
        self, fabric: IdentityFabric, workload_idp: FakeIdp
    ) -> None:
        await activate(fabric, workload_idp)
        token = await credential(fabric, workload_idp)
        await fabric.set_status(agent_uri(), AgentStatus.SUSPENDED, actor="sec", reason="incident")
        await fabric.set_status(agent_uri(), AgentStatus.ACTIVE, actor="sec", reason="cleared")
        with pytest.raises(UnauthorizedError, match="predates"):
            await fabric.validate(token)
        assert not (await fabric.introspect(token)).active
        fresh = await credential(fabric, workload_idp)
        assert (await fabric.validate(fresh)).epoch == 1

    async def test_token_revocation_and_purge(
        self, fabric: IdentityFabric, workload_idp: FakeIdp, clock: FakeClock
    ) -> None:
        await activate(fabric, workload_idp)
        token = await credential(fabric, workload_idp)
        await fabric.revoke_token(token, actor="ops")
        await fabric.revoke_token(token, actor="ops")  # idempotent
        await fabric.revoke_token("garbage", actor="ops")  # RFC 7009: no error
        with pytest.raises(UnauthorizedError, match="revoked"):
            await fabric.validate(token)
        assert await fabric.purge_revocations() == 0
        clock.advance(3600)
        assert await fabric.purge_revocations() == 1

    async def test_expiry_enforced_by_clock(
        self, fabric: IdentityFabric, workload_idp: FakeIdp, clock: FakeClock
    ) -> None:
        await activate(fabric, workload_idp)
        token = await credential(fabric, workload_idp)
        clock.advance(601)
        with pytest.raises(UnauthorizedError, match="Expired"):
            await fabric.validate(token)


class TestDelegation:
    async def setup(self, fabric: IdentityFabric, idp: FakeIdp) -> tuple[str, str]:
        await activate(
            fabric,
            idp,
            "orchestrator",
            scopes=frozenset({"fhir:read:*", "scheduling:read", "billing:read"}),
        )
        await activate(
            fabric,
            idp,
            "scheduler",
            scopes=frozenset({"scheduling:read", "fhir:read:*"}),
            max_classification=DataClassification.CONFIDENTIAL,
            risk=RiskLevel.LOW,
        )
        return (
            await credential(fabric, idp, "orchestrator"),
            await credential(fabric, idp, "scheduler"),
        )

    async def test_attenuated_exchange(self, fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
        subject, actor = await self.setup(fabric, workload_idp)
        issued = await fabric.exchange(subject, actor, scopes=None)
        claims = await fabric.validate(issued.access_token)
        assert claims.sub == agent_uri("orchestrator")
        assert claims.scopes == {"fhir:read:*", "scheduling:read"}  # billing not delegable
        assert claims.act is not None
        assert claims.act.sub == agent_uri("scheduler")
        assert claims.max_cls == int(DataClassification.CONFIDENTIAL)  # actor's ceiling
        assert claims.risk == int(RiskLevel.MODERATE)  # higher of the two

    async def test_cannot_escalate_scopes(
        self, fabric: IdentityFabric, workload_idp: FakeIdp
    ) -> None:
        subject, actor = await self.setup(fabric, workload_idp)
        with pytest.raises(InvalidGrantError, match="exceed"):
            await fabric.exchange(subject, actor, scopes=frozenset({"billing:read"}))

    async def test_self_and_cycles(self, fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
        subject, actor = await self.setup(fabric, workload_idp)
        with pytest.raises(InvalidGrantError, match="itself"):
            await fabric.exchange(subject, subject, scopes=None)
        delegated = await fabric.exchange(subject, actor, scopes=None)
        # orchestrator token held by scheduler cannot be delegated back to scheduler
        with pytest.raises(InvalidGrantError, match="cycle"):
            await fabric.exchange(delegated.access_token, actor, scopes=None)

    async def test_revoked_delegate_breaks_chain(
        self, fabric: IdentityFabric, workload_idp: FakeIdp
    ) -> None:
        subject, actor = await self.setup(fabric, workload_idp)
        delegated = await fabric.exchange(subject, actor, scopes=None)
        await fabric.set_status(
            agent_uri("scheduler"), AgentStatus.REVOKED, actor="sec", reason="compromised"
        )
        with pytest.raises(UnauthorizedError, match="delegate"):
            await fabric.validate(delegated.access_token)

    async def test_delegated_token_cannot_outlive_subject(
        self, fabric: IdentityFabric, workload_idp: FakeIdp, clock: FakeClock
    ) -> None:
        subject, _ = await self.setup(fabric, workload_idp)
        clock.advance(500)
        actor = await credential(fabric, workload_idp, "scheduler")
        issued = await fabric.exchange(subject, actor, scopes=None)
        assert issued.expires_in == 100


class TestAuthorization:
    async def test_decisions(self, fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
        await activate(fabric, workload_idp)
        token = await credential(fabric, workload_idp)
        restricted = Resource(
            type="fhir:Patient", id="p1", classification=DataClassification.RESTRICTED
        )

        allowed = await fabric.authorize(
            token,
            action="fhir:read:patient",
            resource=restricted,
            environment={"purpose_of_use": "TREAT"},
        )
        assert allowed.decision is Decision.ALLOW
        assert allowed.matched_rules == ("allow-scoped-actions",)

        no_purpose = await fabric.authorize(
            token, action="fhir:read:patient", resource=restricted, environment={}
        )
        assert no_purpose.decision is Decision.DENY

        out_of_scope = await fabric.authorize(
            token,
            action="billing:read",
            resource=Resource(type="billing:Invoice"),
            environment={},
        )
        assert out_of_scope.decision is Decision.DENY
        assert "default deny" in out_of_scope.reason

    async def test_classification_ceiling_overrides_policy(
        self, fabric: IdentityFabric, workload_idp: FakeIdp
    ) -> None:
        await activate(fabric, workload_idp, max_classification=DataClassification.INTERNAL)
        token = await credential(fabric, workload_idp)
        decision = await fabric.authorize(
            token,
            action="fhir:read:patient",
            resource=Resource(type="fhir:Patient", classification=DataClassification.CONFIDENTIAL),
            environment={},
        )
        assert decision.decision is Decision.DENY
        assert decision.reason == "resource exceeds agent classification"

    async def test_delegated_write_needs_approval(
        self, fabric: IdentityFabric, workload_idp: FakeIdp
    ) -> None:
        await activate(fabric, workload_idp, "orchestrator", scopes=frozenset({"fhir:write:task"}))
        await activate(fabric, workload_idp, "scheduler", scopes=frozenset({"fhir:write:task"}))
        delegated = await fabric.exchange(
            await credential(fabric, workload_idp, "orchestrator"),
            await credential(fabric, workload_idp, "scheduler"),
            scopes=None,
        )
        decision = await fabric.authorize(
            delegated.access_token,
            action="fhir:write:task",
            resource=Resource(type="fhir:Task"),
            environment={},
        )
        assert decision.decision is Decision.REQUIRE_APPROVAL
        assert decision.delegation_chain == (agent_uri("scheduler"),)

    async def test_critical_agents_need_approval(
        self, fabric: IdentityFabric, workload_idp: FakeIdp
    ) -> None:
        await activate(fabric, workload_idp, risk=RiskLevel.CRITICAL)
        token = await credential(fabric, workload_idp)
        decision = await fabric.authorize(
            token, action="scheduling:read", resource=Resource(type="schedule"), environment={}
        )
        assert decision.decision is Decision.REQUIRE_APPROVAL
