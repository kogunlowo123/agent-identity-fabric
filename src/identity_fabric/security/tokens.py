"""Agent credential issuance, delegation (RFC 8693) and verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from agentic_core.domain.identifiers import new_id

from identity_fabric.domain.errors import InvalidScopeError, UnauthorizedError
from identity_fabric.domain.models import Actor, Agent, IssuedToken, TokenClaims
from identity_fabric.security.keys import KeyRing

ALGORITHM = "EdDSA"
CLOCK_SKEW_S = 30


class TokenService:
    def __init__(
        self,
        keys: KeyRing,
        *,
        issuer: str,
        audience: str,
        default_ttl: timedelta = timedelta(minutes=10),
        max_ttl: timedelta = timedelta(minutes=15),
        max_delegation_depth: int = 3,
    ) -> None:
        if default_ttl > max_ttl:
            raise ValueError("default_ttl exceeds max_ttl")
        self._keys = keys
        self._issuer = issuer
        self._audience = audience
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl
        self._max_depth = max_delegation_depth

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def max_delegation_depth(self) -> int:
        return self._max_depth

    def jwks(self) -> dict[str, Any]:
        return self._keys.jwks()

    def issue(
        self,
        agent: Agent,
        *,
        now: datetime,
        requested_scopes: frozenset[str] | None = None,
        ttl: timedelta | None = None,
        actor: Actor | None = None,
        not_after: datetime | None = None,
    ) -> tuple[IssuedToken, TokenClaims]:
        scopes = agent.scopes if requested_scopes is None else requested_scopes
        excess = scopes - agent.scopes
        if excess:
            raise InvalidScopeError(f"scopes not granted to agent: {sorted(excess)}")
        if not scopes:
            raise InvalidScopeError("at least one scope is required")
        if actor is not None and actor.depth() > self._max_depth:
            raise InvalidScopeError(f"delegation depth exceeds {self._max_depth}")

        lifetime = min(ttl or self._default_ttl, self._max_ttl)
        expires = now + lifetime
        if not_after is not None:
            expires = min(expires, not_after)
        if expires <= now:
            raise InvalidScopeError("parent credential has expired")

        claims = TokenClaims(
            iss=self._issuer,
            sub=agent.uri,
            aud=self._audience,
            jti=new_id(),
            iat=int(now.timestamp()),
            exp=int(expires.timestamp()),
            scope=" ".join(sorted(scopes)),
            risk=int(agent.risk),
            max_cls=int(agent.max_classification),
            epoch=agent.credential_epoch,
            act=actor,
        )
        signing = self._keys.active
        token = jwt.encode(
            claims.model_dump(mode="json", exclude_none=True),
            signing.private_key,
            algorithm=ALGORITHM,
            headers={"kid": signing.kid, "typ": "at+jwt"},
        )
        return (
            IssuedToken(
                access_token=token,
                expires_in=int((expires - now).total_seconds()),
                scope=claims.scope,
            ),
            claims,
        )

    def verify(self, token: str, *, now: datetime | None = None) -> TokenClaims:
        """Verify signature and standard claims. Status/revocation checks are the caller's.

        Time claims are checked against ``now`` (the service clock) rather than
        the library's wall clock so every component agrees on the current time.
        """
        current = int((now or datetime.now(UTC)).timestamp())
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("malformed token") from exc
        if header.get("alg") != ALGORITHM:
            raise UnauthorizedError("unexpected token algorithm")
        kid = header.get("kid")
        key = self._keys.public_key(kid) if isinstance(kid, str) else None
        if key is None:
            raise UnauthorizedError("unknown signing key")
        try:
            payload = jwt.decode(
                token,
                key=key,
                algorithms=[ALGORITHM],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "require": ["exp", "iat", "iss", "sub", "aud", "jti"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise UnauthorizedError(f"token rejected: {type(exc).__name__}") from exc
        claims = TokenClaims.model_validate(payload)
        if claims.exp <= current:
            raise UnauthorizedError("token rejected: ExpiredSignatureError")
        if claims.iat > current + CLOCK_SKEW_S:
            raise UnauthorizedError("token rejected: ImmatureSignatureError")
        return claims

    @staticmethod
    def expiry(claims: TokenClaims) -> datetime:
        return datetime.fromtimestamp(claims.exp, tz=UTC)
