"""Runtime settings, read from FABRIC_* environment variables."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from pydantic import Field, HttpUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FABRIC_", env_nested_delimiter="__")

    environment: str = "production"
    trust_domain: str = Field(description="SPIFFE trust domain, e.g. agents.corp.internal")
    issuer: HttpUrl = Field(description="Public URL of this fabric; the iss claim")
    audience: str = Field(default="agent-platform", description="aud claim of agent credentials")

    database_url: str = Field(description="SQLAlchemy async URL, e.g. postgresql+asyncpg://...")

    signing_keys_dir: Path | None = None
    active_kid: str | None = None
    audit_key_file: Path | None = None
    audit_log_path: Path = Path("/var/lib/identity-fabric/audit/audit.jsonl")
    dev_ephemeral_keys: bool = Field(
        default=False,
        description="Generate in-memory keys at start-up. Refused when environment=production.",
    )

    workload_issuers: dict[str, str] = Field(
        default_factory=dict, description="Trusted workload token issuer URL -> JWKS URL"
    )
    admin_issuer: str = Field(description="Enterprise OIDC issuer for administrators")
    admin_audience: str = Field(description="Audience administrators' tokens must carry")
    admin_jwks_url: str
    admin_roles_claim: str = "roles"

    policy_file: Path = Path("policies/agent-authorization.yaml")
    token_ttl_seconds: int = Field(default=600, ge=60, le=900)
    max_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    max_delegation_depth: int = Field(default=3, ge=1, le=10)

    log_level: str = "INFO"
    otlp_endpoint: str | None = None

    @model_validator(mode="after")
    def _keys(self) -> Settings:
        if self.dev_ephemeral_keys:
            if self.environment == "production":
                raise ValueError("dev_ephemeral_keys cannot be used in production")
            return self
        missing = [
            name
            for name, value in (
                ("FABRIC_SIGNING_KEYS_DIR", self.signing_keys_dir),
                ("FABRIC_ACTIVE_KID", self.active_kid),
                ("FABRIC_AUDIT_KEY_FILE", self.audit_key_file),
            )
            if value is None
        ]
        if missing:
            raise ValueError(f"signing configuration incomplete: {missing}")
        if not self.workload_issuers:
            raise ValueError("at least one trusted workload issuer is required")
        return self

    @property
    def token_ttl(self) -> timedelta:
        return timedelta(seconds=self.token_ttl_seconds)

    @property
    def max_token_ttl(self) -> timedelta:
        return timedelta(seconds=self.max_token_ttl_seconds)

    @property
    def issuer_str(self) -> str:
        return str(self.issuer).rstrip("/")
