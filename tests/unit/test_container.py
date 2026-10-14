"""Production wiring: keys and audit signer loaded from mounted secret files."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity_fabric.config import Settings
from identity_fabric.runtime.container import build_container
from identity_fabric.security.jwks import RemoteJwks, StaticJwks
from tests.conftest import ROOT, WORKLOAD_ISSUER, FakeIdp


def write_pem(path: Path, key: object) -> None:
    path.write_bytes(
        key.private_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def production_settings(tmp_path: Path, audit_key: Path) -> Settings:
    keys = tmp_path / "keys"
    keys.mkdir()
    write_pem(keys / "2026-10.pem", Ed25519PrivateKey.generate())
    return Settings(
        trust_domain="agents.corp.test",
        issuer="https://identity.corp.test",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'p.db'}",
        signing_keys_dir=keys,
        active_kid="2026-10",
        audit_key_file=audit_key,
        audit_log_path=tmp_path / "audit.jsonl",
        workload_issuers={WORKLOAD_ISSUER: "https://oidc.example/jwks"},
        admin_issuer="https://login.corp.test",
        admin_audience="adm",
        admin_jwks_url="https://login.corp.test/jwks",
        policy_file=ROOT / "policies" / "agent-authorization.yaml",
    )


async def test_production_wiring(tmp_path: Path, admin_idp: FakeIdp) -> None:
    audit_key = tmp_path / "audit-2026-10.pem"
    write_pem(audit_key, Ed25519PrivateKey.generate())
    container = await build_container(
        production_settings(tmp_path, audit_key), admin_resolver=StaticJwks(admin_idp.jwks())
    )
    try:
        assert container.fabric.tokens.jwks()["keys"][0]["kid"] == "2026-10"
        assert container.fabric._audit._key_id == "audit-2026-10"
        resolver = container.fabric._attestor._resolvers[WORKLOAD_ISSUER]
        assert isinstance(resolver, RemoteJwks)
    finally:
        await container.aclose()


async def test_rejects_non_ed25519_audit_key(tmp_path: Path) -> None:
    audit_key = tmp_path / "audit.pem"
    write_pem(audit_key, generate_private_key(SECP256R1()))
    with pytest.raises(ValueError, match="audit key must be Ed25519"):
        await build_container(production_settings(tmp_path, audit_key))
