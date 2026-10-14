"""Dependency container built once per process from Settings."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import httpx
from agentic_core.audit import AuditLog, JsonlAuditSink
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncEngine

from identity_fabric.application.service import IdentityFabric
from identity_fabric.config import Settings
from identity_fabric.domain.ports import Clock
from identity_fabric.infrastructure.database import (
    SqlAgentRepository,
    SqlRevocationStore,
    SystemClock,
    create_schema,
    make_engine,
)
from identity_fabric.observability.metrics import FabricMetrics
from identity_fabric.security.admin import AdminAuthenticator
from identity_fabric.security.attestation import WorkloadAttestor
from identity_fabric.security.jwks import KeyResolver, RemoteJwks
from identity_fabric.security.keys import KeyRing
from identity_fabric.security.tokens import TokenService


@dataclass
class Container:
    settings: Settings
    fabric: IdentityFabric
    admin: AdminAuthenticator
    metrics: FabricMetrics
    engine: AsyncEngine
    http: httpx.AsyncClient

    async def aclose(self) -> None:
        await self.http.aclose()
        await self.engine.dispose()


def _audit_signer(settings: Settings) -> tuple[Ed25519PrivateKey, str]:
    if settings.audit_key_file is None:
        return Ed25519PrivateKey.generate(), "audit-ephemeral"
    key = serialization.load_pem_private_key(settings.audit_key_file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("audit key must be Ed25519")
    return key, settings.audit_key_file.stem


async def build_container(
    settings: Settings,
    *,
    workload_resolvers: Mapping[str, KeyResolver] | None = None,
    admin_resolver: KeyResolver | None = None,
    clock: Clock | None = None,
    http: httpx.AsyncClient | None = None,
) -> Container:
    http = http or httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    if settings.dev_ephemeral_keys:
        keys = KeyRing.ephemeral()
    else:
        if settings.signing_keys_dir is None or settings.active_kid is None:
            raise ValueError("signing keys are not configured")  # pragma: no cover - validated
        keys = KeyRing.from_directory(settings.signing_keys_dir, active_kid=settings.active_kid)

    resolvers: dict[str, KeyResolver] = dict(workload_resolvers or {})
    for issuer, jwks_url in settings.workload_issuers.items():
        resolvers.setdefault(issuer, RemoteJwks(jwks_url, client=http))

    engine = make_engine(settings.database_url)
    await create_schema(engine)

    signer, key_id = _audit_signer(settings)
    audit = AuditLog(JsonlAuditSink(settings.audit_log_path), signer, key_id=key_id)

    fabric = IdentityFabric(
        trust_domain=settings.trust_domain,
        agents=SqlAgentRepository(engine),
        revocations=SqlRevocationStore(engine),
        tokens=TokenService(
            keys,
            issuer=settings.issuer_str,
            audience=settings.audience,
            default_ttl=settings.token_ttl,
            max_ttl=settings.max_token_ttl,
            max_delegation_depth=settings.max_delegation_depth,
        ),
        attestor=WorkloadAttestor(resolvers),
        policy=PolicyEngine(PolicySet.from_file(settings.policy_file)),
        audit=audit,
        clock=clock or SystemClock(),
    )
    admin = AdminAuthenticator(
        admin_resolver or RemoteJwks(settings.admin_jwks_url, client=http),
        issuer=settings.admin_issuer,
        audience=settings.admin_audience,
        roles_claim=settings.admin_roles_claim,
    )
    return Container(
        settings=settings,
        fabric=fabric,
        admin=admin,
        metrics=FabricMetrics(),
        engine=engine,
        http=http,
    )
