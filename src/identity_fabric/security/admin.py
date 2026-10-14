"""Administrator authentication via the enterprise OIDC provider."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from identity_fabric.domain.errors import ForbiddenError, UnauthorizedError
from identity_fabric.security.jwks import KeyResolver, verify_jwt


class AdminPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    roles: frozenset[str]


class AdminRole:
    REGISTRAR = "agent-registrar"  # register agents, read inventory
    SECURITY = "agent-security-officer"  # suspend, reinstate, revoke
    AUDITOR = "agent-auditor"  # read-only inventory


class AdminAuthenticator:
    def __init__(
        self, resolver: KeyResolver, *, issuer: str, audience: str, roles_claim: str = "roles"
    ) -> None:
        self._resolver = resolver
        self._issuer = issuer
        self._audience = audience
        self._roles_claim = roles_claim

    async def authenticate(self, authorization: str | None) -> AdminPrincipal:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise UnauthorizedError("bearer token required")
        claims = await verify_jwt(
            authorization[7:].strip(), self._resolver, issuer=self._issuer, audience=self._audience
        )
        raw = claims.get(self._roles_claim, [])
        roles = (
            frozenset(r for r in raw if isinstance(r, str))
            if isinstance(raw, list)
            else frozenset()
        )
        return AdminPrincipal(subject=str(claims["sub"]), roles=roles)


def require_role(principal: AdminPrincipal, *allowed: str) -> None:
    if not principal.roles.intersection(allowed):
        raise ForbiddenError(f"requires one of roles {sorted(allowed)}")
