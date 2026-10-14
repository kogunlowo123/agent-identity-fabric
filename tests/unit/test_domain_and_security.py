from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from pydantic import ValidationError

from identity_fabric.config import Settings
from identity_fabric.domain.errors import (
    AttestationError,
    ForbiddenError,
    InvalidScopeError,
    InvalidStateError,
    UnauthorizedError,
)
from identity_fabric.domain.models import Actor, AgentStatus, WorkloadBinding, validate_scopes
from identity_fabric.security.admin import AdminAuthenticator, AdminRole, require_role
from identity_fabric.security.attestation import WorkloadAttestor
from identity_fabric.security.jwks import RemoteJwks, StaticJwks, verify_jwt
from identity_fabric.security.keys import KeyRing, SigningKey
from identity_fabric.security.tokens import TokenService
from tests.conftest import (
    DIGEST,
    WORKLOAD_ISSUER,
    FakeIdp,
    registration,
    workload_token,
)


def make_agent(**kw: object):  # type: ignore[no-untyped-def]
    from agentic_core.domain.identifiers import AgentId

    from identity_fabric.domain.models import Agent

    reg = registration(**kw)  # type: ignore[arg-type]
    now = datetime.now(UTC)
    return Agent(
        agent_id=AgentId(trust_domain="agents.corp.test", namespace=reg.namespace, name=reg.name),
        display_name=reg.display_name,
        mandate=reg.mandate,
        scopes=reg.scopes,
        risk=reg.risk,
        max_classification=reg.max_classification,
        workload=reg.workload,
        created_at=now,
        updated_at=now,
    )


class TestModels:
    def test_lifecycle_transitions(self) -> None:
        agent = make_agent()
        now = datetime.now(UTC)
        active = agent.transition(AgentStatus.ACTIVE, at=now, reason="attested")
        assert active.attested_at == now
        suspended = active.transition(AgentStatus.SUSPENDED, at=now, reason="incident")
        assert suspended.credential_epoch == 1
        reinstated = suspended.transition(AgentStatus.ACTIVE, at=now, reason="cleared")
        assert reinstated.attested_at == now  # unchanged by reinstatement
        revoked = reinstated.transition(AgentStatus.REVOKED, at=now, reason="retired")
        assert revoked.credential_epoch == 2
        with pytest.raises(InvalidStateError):
            revoked.transition(AgentStatus.ACTIVE, at=now, reason="no")

    @pytest.mark.parametrize("scope", ["FHIR:read", "read", "fhir:", "fhir read:x", ":x"])
    def test_rejects_bad_scopes(self, scope: str) -> None:
        with pytest.raises(ValueError, match="invalid scopes"):
            validate_scopes(frozenset({scope}))

    def test_bad_digest(self) -> None:
        with pytest.raises(ValidationError, match="invalid image digests"):
            WorkloadBinding(issuer="i", subject="s", audience="a", image_digests=frozenset({"x"}))

    def test_actor_chain(self) -> None:
        chain = Actor(sub="b", act=Actor(sub="a"))
        assert chain.depth() == 2
        assert chain.subjects() == ["b", "a"]


class TestKeys:
    def test_from_directory_and_rotation(self, tmp_path: Path) -> None:
        for kid in ("2026-09", "2026-10"):
            pem = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            (tmp_path / f"{kid}.pem").write_bytes(pem)
        ring = KeyRing.from_directory(tmp_path, active_kid="2026-10")
        assert ring.active.kid == "2026-10"
        assert {k["kid"] for k in ring.jwks()["keys"]} == {"2026-09", "2026-10"}
        assert ring.public_key("2026-09") is not None
        assert ring.public_key("missing") is None
        assert ring.active.sign(b"x")

    def test_rejects_non_ed25519(self, tmp_path: Path) -> None:
        pem = generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        (tmp_path / "rsa.pem").write_bytes(pem)
        with pytest.raises(ValueError, match="only Ed25519"):
            KeyRing.from_directory(tmp_path, active_kid="rsa")

    def test_validation(self) -> None:
        key = SigningKey("a", Ed25519PrivateKey.generate())
        with pytest.raises(ValueError, match="empty"):
            KeyRing([], active_kid="a")
        with pytest.raises(ValueError, match="duplicate"):
            KeyRing([key, key], active_kid="a")
        with pytest.raises(ValueError, match="not present"):
            KeyRing([key], active_kid="b")


class TestTokenService:
    def service(self, **kw: object) -> TokenService:
        return TokenService(KeyRing.ephemeral(), issuer="https://i", audience="aud", **kw)  # type: ignore[arg-type]

    def test_issue_and_verify(self) -> None:
        svc = self.service()
        agent = make_agent()
        now = datetime.now(UTC)
        issued, claims = svc.issue(agent, now=now, requested_scopes=frozenset({"scheduling:read"}))
        assert issued.expires_in == 600
        verified = svc.verify(issued.access_token, now=now)
        assert verified == claims
        assert verified.scopes == {"scheduling:read"}

    def test_ttl_capped_and_bounded_by_parent(self) -> None:
        svc = self.service()
        now = datetime.now(UTC)
        issued, _ = svc.issue(make_agent(), now=now, ttl=timedelta(hours=2))
        assert issued.expires_in == 900
        issued, _ = svc.issue(make_agent(), now=now, not_after=now + timedelta(seconds=42))
        assert issued.expires_in == 42
        with pytest.raises(InvalidScopeError, match="expired"):
            svc.issue(make_agent(), now=now, not_after=now)

    def test_scope_and_depth_limits(self) -> None:
        svc = self.service(max_delegation_depth=1)
        now = datetime.now(UTC)
        with pytest.raises(InvalidScopeError, match="not granted"):
            svc.issue(make_agent(), now=now, requested_scopes=frozenset({"billing:read"}))
        with pytest.raises(InvalidScopeError, match="at least one"):
            svc.issue(make_agent(), now=now, requested_scopes=frozenset())
        with pytest.raises(InvalidScopeError, match="depth"):
            svc.issue(make_agent(), now=now, actor=Actor(sub="a", act=Actor(sub="b")))

    def test_config_validation(self) -> None:
        with pytest.raises(ValueError, match="default_ttl"):
            self.service(default_ttl=timedelta(hours=1))

    def test_verify_rejections(self) -> None:
        svc = self.service()
        now = datetime.now(UTC)
        issued, _ = svc.issue(make_agent(), now=now)
        with pytest.raises(UnauthorizedError, match="Expired"):
            svc.verify(issued.access_token, now=now + timedelta(hours=1))
        with pytest.raises(UnauthorizedError, match="malformed"):
            svc.verify("not-a-jwt")
        same_kid_other_key = self.service()
        with pytest.raises(UnauthorizedError, match="InvalidSignature"):
            same_kid_other_key.verify(issued.access_token)
        other = TokenService(KeyRing.ephemeral("rotated"), issuer="https://i", audience="aud")
        with pytest.raises(UnauthorizedError, match="unknown signing key"):
            other.verify(issued.access_token)
        future, _ = svc.issue(make_agent(), now=now + timedelta(minutes=5))
        with pytest.raises(UnauthorizedError, match="Immature"):
            svc.verify(future.access_token, now=now)
        hs = jwt.encode({"sub": "x"}, "k" * 32, algorithm="HS256")
        with pytest.raises(UnauthorizedError, match="algorithm"):
            svc.verify(hs)
        wrong_aud = TokenService(svc._keys, issuer="https://i", audience="other")
        with pytest.raises(UnauthorizedError, match="InvalidAudience"):
            wrong_aud.verify(issued.access_token)


class TestJwks:
    async def test_static(self, workload_idp: FakeIdp) -> None:
        resolver = StaticJwks(workload_idp.jwks())
        assert await resolver.key_for("k1") is not None
        with pytest.raises(UnauthorizedError, match="unknown"):
            await resolver.key_for("nope")

    async def test_remote_cache_refresh_and_rate_limit(self, workload_idp: FakeIdp) -> None:
        calls = {"n": 0}

        def handler(_: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json=workload_idp.jwks())

        now = [0.0]
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            remote = RemoteJwks(
                "https://x/jwks",
                client=http,
                ttl_s=100,
                min_refresh_interval_s=10,
                clock=lambda: now[0],
            )
            await remote.key_for("k1")
            await remote.key_for("k1")
            assert calls["n"] == 1
            with pytest.raises(UnauthorizedError, match="unknown"):
                await remote.key_for("rotated")  # within min interval: no refetch
            assert calls["n"] == 1
            now[0] = 11
            with pytest.raises(UnauthorizedError):
                await remote.key_for("rotated")  # refetch allowed
            assert calls["n"] == 2
            now[0] = 200
            await remote.key_for("k1")  # ttl expired
            assert calls["n"] == 3

    async def test_remote_outage_uses_cache(self, workload_idp: FakeIdp) -> None:
        healthy = {"ok": True}

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200 if healthy["ok"] else 503, json=workload_idp.jwks())

        now = [0.0]
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            remote = RemoteJwks("https://x/jwks", client=http, ttl_s=5, clock=lambda: now[0])
            await remote.key_for("k1")
            healthy["ok"] = False
            now[0] = 100
            assert await remote.key_for("k1") is not None  # stale cache tolerated
            with pytest.raises(UnauthorizedError, match="cannot fetch"):
                await remote.key_for("other")

    async def test_verify_jwt_rejections(self, workload_idp: FakeIdp) -> None:
        resolver = StaticJwks(workload_idp.jwks())
        good = workload_idp.mint(sub="s", aud="a")
        assert (await verify_jwt(good, resolver, issuer=WORKLOAD_ISSUER, audience="a"))[
            "sub"
        ] == "s"
        with pytest.raises(UnauthorizedError, match="malformed"):
            await verify_jwt("garbage", resolver, issuer=WORKLOAD_ISSUER, audience="a")
        unsigned = jwt.encode({"sub": "s"}, key=None, algorithm="none")
        with pytest.raises(UnauthorizedError, match="not accepted"):
            await verify_jwt(unsigned, resolver, issuer=WORKLOAD_ISSUER, audience="a")
        with pytest.raises(UnauthorizedError, match="InvalidAudience"):
            await verify_jwt(good, resolver, issuer=WORKLOAD_ISSUER, audience="b")


class TestAttestation:
    async def test_success_and_failures(self, workload_idp: FakeIdp) -> None:
        attestor = WorkloadAttestor({WORKLOAD_ISSUER: StaticJwks(workload_idp.jwks())})
        agent = make_agent()
        result = await attestor.attest(agent, workload_token(workload_idp))
        assert result.image_digest == DIGEST

        with pytest.raises(AttestationError, match="subject"):
            await attestor.attest(agent, workload_token(workload_idp, name="impostor"))
        with pytest.raises(AttestationError, match="digest"):
            await attestor.attest(
                agent, workload_token(workload_idp, image_digest="sha256:" + "b" * 64)
            )
        with pytest.raises(AttestationError, match="invalid"):
            await attestor.attest(
                agent, FakeIdp(WORKLOAD_ISSUER).mint(sub="x", aud="identity-fabric")
            )
        with pytest.raises(AttestationError, match="not trusted"):
            await WorkloadAttestor({}).attest(agent, workload_token(workload_idp))

    async def test_kubernetes_claim_shape_and_no_digest_policy(self, workload_idp: FakeIdp) -> None:
        attestor = WorkloadAttestor({WORKLOAD_ISSUER: StaticJwks(workload_idp.jwks())})
        token = workload_idp.mint(
            sub="system:serviceaccount:clinical:care-coordinator",
            aud="identity-fabric",
            **{"kubernetes.io": {"pod": {"image_digest": DIGEST}}},
        )
        assert (await attestor.attest(make_agent(), token)).image_digest == DIGEST
        unpinned = make_agent(digests=frozenset())
        bare = workload_idp.mint(
            sub="system:serviceaccount:clinical:care-coordinator", aud="identity-fabric"
        )
        assert (await attestor.attest(unpinned, bare)).image_digest is None


class TestAdmin:
    async def test_roles(self, admin_idp: FakeIdp) -> None:
        auth = AdminAuthenticator(
            StaticJwks(admin_idp.jwks()), issuer=admin_idp.issuer, audience="adm"
        )
        token = admin_idp.mint(sub="alice", aud="adm", roles=[AdminRole.SECURITY, 7])
        principal = await auth.authenticate(f"Bearer {token}")
        assert principal.roles == {AdminRole.SECURITY}
        require_role(principal, AdminRole.SECURITY)
        with pytest.raises(ForbiddenError):
            require_role(principal, AdminRole.REGISTRAR)
        no_roles = await auth.authenticate(
            f"Bearer {admin_idp.mint(sub='b', aud='adm', roles='x')}"
        )
        assert no_roles.roles == frozenset()
        with pytest.raises(UnauthorizedError, match="bearer"):
            await auth.authenticate(None)


class TestSettings:
    BASE: ClassVar[dict[str, str]] = {
        "trust_domain": "d",
        "issuer": "https://i",
        "database_url": "sqlite+aiosqlite:///x",
        "admin_issuer": "https://a",
        "admin_audience": "a",
        "admin_jwks_url": "https://a/jwks",
    }

    def test_production_rejects_ephemeral_keys(self) -> None:
        with pytest.raises(ValidationError, match="cannot be used in production"):
            Settings(**self.BASE, dev_ephemeral_keys=True)  # type: ignore[arg-type]

    def test_requires_keys_and_issuers(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="FABRIC_SIGNING_KEYS_DIR"):
            Settings(**self.BASE)  # type: ignore[arg-type]
        with pytest.raises(ValidationError, match="workload issuer"):
            Settings(
                **self.BASE,  # type: ignore[arg-type]
                signing_keys_dir=tmp_path,
                active_kid="k",
                audit_key_file=tmp_path / "a.pem",
            )

    def test_properties(self) -> None:
        s = Settings(**self.BASE, environment="dev", dev_ephemeral_keys=True)  # type: ignore[arg-type]
        assert s.issuer_str == "https://i"
        assert s.token_ttl == timedelta(seconds=600)
        assert s.max_token_ttl == timedelta(seconds=900)
