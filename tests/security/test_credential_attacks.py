"""Adversarial credential tests mapped to the threat model (docs/security/threat-model.md)."""

from __future__ import annotations

import base64
import json

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity_fabric.application.service import IdentityFabric
from identity_fabric.domain.errors import InvalidGrantError, UnauthorizedError
from identity_fabric.runtime.container import Container
from tests.conftest import FakeIdp, agent_uri, workload_token
from tests.unit.test_fabric_service import activate, credential

pytestmark = pytest.mark.security


def _b64(obj: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


async def test_t1_forged_signature(fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
    """T1 spoofing: a token signed by an attacker key with a guessed kid is rejected."""
    await activate(fabric, workload_idp)
    genuine = jwt.decode(
        await credential(fabric, workload_idp), options={"verify_signature": False}
    )
    kid = jwt.get_unverified_header(await credential(fabric, workload_idp))["kid"]
    forged = jwt.encode(
        genuine, Ed25519PrivateKey.generate(), algorithm="EdDSA", headers={"kid": kid}
    )
    with pytest.raises(UnauthorizedError, match="InvalidSignature"):
        await fabric.validate(forged)


async def test_t2_alg_none(fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
    await activate(fabric, workload_idp)
    claims = jwt.decode(await credential(fabric, workload_idp), options={"verify_signature": False})
    unsigned = f"{_b64({'alg': 'none', 'kid': 'ephemeral'})}.{_b64(claims)}."
    with pytest.raises(UnauthorizedError):
        await fabric.validate(unsigned)


async def test_t3_payload_tampering(fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
    """Swapping in broader scopes invalidates the signature."""
    await activate(fabric, workload_idp)
    header, payload, sig = (await credential(fabric, workload_idp)).split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["scope"] = "admin:*"
    with pytest.raises(UnauthorizedError):
        await fabric.validate(f"{header}.{_b64(claims)}.{sig}")


async def test_t4_workload_token_replayed_as_agent_credential(
    fabric: IdentityFabric, workload_idp: FakeIdp
) -> None:
    """Audience confusion: a workload token is not an agent credential."""
    await activate(fabric, workload_idp)
    with pytest.raises(UnauthorizedError):
        await fabric.validate(workload_token(workload_idp))


async def test_t5_expired_workload_token(fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
    await activate(fabric, workload_idp)
    stale = workload_idp.mint(
        sub="system:serviceaccount:clinical:care-coordinator",
        aud="identity-fabric",
        ttl=-120,
        image_digest="sha256:" + "a" * 64,
    )
    with pytest.raises(InvalidGrantError):
        await fabric.issue_for_workload(agent_uri(), stale, scopes=None)


async def test_t6_scope_escalation_at_issuance(
    fabric: IdentityFabric, workload_idp: FakeIdp
) -> None:
    await activate(fabric, workload_idp)
    with pytest.raises(Exception, match="not granted"):
        await credential(fabric, workload_idp, scopes=frozenset({"fhir:delete:patient"}))


async def test_t7_cross_agent_workload_token(fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
    """Agent B's workload cannot obtain agent A's credential."""
    await activate(fabric, workload_idp, "agent-a")
    await activate(fabric, workload_idp, "agent-b")
    with pytest.raises(InvalidGrantError):
        await fabric.issue_for_workload(
            agent_uri("agent-a"), workload_token(workload_idp, "agent-b"), scopes=None
        )


async def test_t8_delegation_depth_limit(fabric: IdentityFabric, workload_idp: FakeIdp) -> None:
    names = ["a0", "a1", "a2", "a3", "a4"]
    for name in names:
        await activate(fabric, workload_idp, name, scopes=frozenset({"scheduling:read"}))
    token = await credential(fabric, workload_idp, names[0])
    limit = fabric.tokens.max_delegation_depth
    for name in names[1 : limit + 1]:
        actor = await credential(fabric, workload_idp, name)
        token = (await fabric.exchange(token, actor, scopes=None)).access_token
    one_too_many = await credential(fabric, workload_idp, names[limit + 1])
    with pytest.raises(Exception, match="depth"):
        await fabric.exchange(token, one_too_many, scopes=None)


async def test_t9_token_issued_before_revocation_dies(
    fabric: IdentityFabric, workload_idp: FakeIdp
) -> None:
    from identity_fabric.domain.models import AgentStatus

    await activate(fabric, workload_idp)
    token = await credential(fabric, workload_idp)
    await fabric.set_status(agent_uri(), AgentStatus.REVOKED, actor="sec", reason="compromised")
    with pytest.raises(UnauthorizedError):
        await fabric.validate(token)


async def test_t10_audit_chain_is_intact_after_lifecycle(
    container: Container, workload_idp: FakeIdp
) -> None:
    from agentic_core.audit import verify_chain

    fabric = container.fabric
    await activate(fabric, workload_idp)
    await credential(fabric, workload_idp)
    sink = fabric._audit._sink
    events = [e async for e in sink.read()]
    public = fabric._audit._signer.public_key()
    assert verify_chain(events, {events[0].key_id: public}) == len(events)
    assert {e.action for e in events} >= {"agent.register", "agent.attest", "token.issue"}
    serialized = "".join(e.model_dump_json() for e in events)
    assert "eyJ" not in serialized  # no credential material in the audit trail
