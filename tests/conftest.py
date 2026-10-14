"""Shared fixtures: in-process identity providers, a fabric wired to SQLite, and an app."""

from __future__ import annotations

import os
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
from agentic_core.domain.classification import DataClassification, RiskLevel
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from identity_fabric.api.app import create_app
from identity_fabric.application.service import IdentityFabric, RegisterAgent
from identity_fabric.config import Settings
from identity_fabric.domain.models import AgentMandate, WorkloadBinding
from identity_fabric.runtime.container import Container, build_container
from identity_fabric.security.jwks import StaticJwks

ROOT = Path(__file__).resolve().parents[1]
WORKLOAD_ISSUER = "https://oidc.eks.us-east-1.amazonaws.com/id/TESTCLUSTER"
ADMIN_ISSUER = "https://login.corp.test/tenant"
DIGEST = "sha256:" + "a" * 64


@dataclass
class FakeIdp:
    """Minimal OIDC issuer: ES256 keypair plus JWKS."""

    issuer: str
    kid: str = "k1"
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}

    def mint(self, *, sub: str, aud: str, ttl: int = 300, **extra: Any) -> str:
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl}
        claims.update(extra)
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})


@dataclass
class FakeClock:
    current: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


@pytest.fixture
def workload_idp() -> FakeIdp:
    return FakeIdp(WORKLOAD_ISSUER)


@pytest.fixture
def admin_idp() -> FakeIdp:
    return FakeIdp(ADMIN_ISSUER, kid="admin-1")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    db = os.environ.get("FABRIC_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'f.db'}")
    return Settings(
        environment="test",
        trust_domain="agents.corp.test",
        issuer="https://identity.corp.test",
        audience="agent-platform",
        database_url=db,
        dev_ephemeral_keys=True,
        audit_log_path=tmp_path / "audit.jsonl",
        workload_issuers={WORKLOAD_ISSUER: "https://unused.invalid/jwks"},
        admin_issuer=ADMIN_ISSUER,
        admin_audience="identity-fabric-admin",
        admin_jwks_url="https://unused.invalid/admin-jwks",
        policy_file=ROOT / "policies" / "agent-authorization.yaml",
    )


@pytest.fixture
async def container(
    settings: Settings, workload_idp: FakeIdp, admin_idp: FakeIdp, clock: FakeClock
) -> AsyncIterator[Container]:
    built = await build_container(
        settings,
        workload_resolvers={WORKLOAD_ISSUER: StaticJwks(workload_idp.jwks())},
        admin_resolver=StaticJwks(admin_idp.jwks()),
        clock=clock,
    )
    yield built
    await built.aclose()


@pytest.fixture
def fabric(container: Container) -> IdentityFabric:
    return container.fabric


def registration(
    name: str = "care-coordinator",
    *,
    scopes: frozenset[str] = frozenset({"fhir:read:*", "fhir:write:task", "scheduling:read"}),
    risk: RiskLevel = RiskLevel.MODERATE,
    max_classification: DataClassification = DataClassification.RESTRICTED,
    digests: frozenset[str] = frozenset({DIGEST}),
) -> RegisterAgent:
    return RegisterAgent(
        namespace="clinical",
        name=name,
        display_name=f"{name} agent",
        mandate=AgentMandate(
            mission="Coordinate follow-up care tasks for discharged patients.",
            business_owner="care-management",
            technical_owner="clinical-platform",
            protected_resources=("fhir:Patient", "fhir:Task"),
            disallowed_actions=("fhir:delete:*",),
            escalation_contact="care-ops-oncall",
        ),
        scopes=scopes,
        risk=risk,
        max_classification=max_classification,
        workload=WorkloadBinding(
            issuer=WORKLOAD_ISSUER,
            subject=f"system:serviceaccount:clinical:{name}",
            audience="identity-fabric",
            image_digests=digests,
        ),
    )


def workload_token(idp: FakeIdp, name: str = "care-coordinator", **extra: Any) -> str:
    extra.setdefault("image_digest", DIGEST)
    return idp.mint(sub=f"system:serviceaccount:clinical:{name}", aud="identity-fabric", **extra)


def agent_uri(name: str = "care-coordinator") -> str:
    return f"spiffe://agents.corp.test/agent/clinical/{name}"


def admin_headers(idp: FakeIdp, *roles: str) -> dict[str, str]:
    token = idp.mint(sub="alice@corp.test", aud="identity-fabric-admin", roles=list(roles))
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(
    settings: Settings, workload_idp: FakeIdp, admin_idp: FakeIdp, clock: FakeClock
) -> Iterator[TestClient]:
    """App whose container is built inside the app's own event loop by its lifespan."""

    async def factory() -> Container:
        return await build_container(
            settings,
            workload_resolvers={WORKLOAD_ISSUER: StaticJwks(workload_idp.jwks())},
            admin_resolver=StaticJwks(admin_idp.jwks()),
            clock=clock,
        )

    with TestClient(create_app(factory)) as test_client:
        yield test_client
