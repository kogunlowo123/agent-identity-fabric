"""HTTP routes.

Administrative endpoints (``/v1/agents``) require an enterprise OIDC token
with the right role. OAuth endpoints (``/oauth2/*``) follow RFC 6749/7523/
8693/7662/7009 wire formats so standard client libraries work unchanged.
"""

from __future__ import annotations

from typing import Annotated

from agentic_core.policy import Resource
from fastapi import APIRouter, Depends, Form, Header, Query, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from identity_fabric.api.schemas import (
    AgentList,
    AgentView,
    AttestRequest,
    AuthorizeRequest,
    StatusChange,
)
from identity_fabric.application.service import (
    AuthorizationDecision,
    Introspection,
    RegisterAgent,
)
from identity_fabric.domain.errors import FabricError, InvalidGrantError, UnauthorizedError
from identity_fabric.domain.models import AgentStatus, IssuedToken
from identity_fabric.runtime.container import Container
from identity_fabric.security.admin import AdminPrincipal, AdminRole, require_role

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
# RFC 8693 grant type identifier, not a credential.
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105  # nosec B105
JWT_TOKEN_TYPES = {
    "urn:ietf:params:oauth:token-type:jwt",
    "urn:ietf:params:oauth:token-type:access_token",
}

router = APIRouter()


def container(request: Request) -> Container:
    value: Container = request.app.state.container
    return value


async def admin(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> AdminPrincipal:
    return await container(request).admin.authenticate(authorization)


def bearer(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UnauthorizedError("agent bearer token required")
    return authorization[7:].strip()


Deps = Annotated[Container, Depends(container)]
Admin = Annotated[AdminPrincipal, Depends(admin)]


# ------------------------------------------------------------------ discovery


@router.get("/.well-known/jwks.json", tags=["discovery"])
async def jwks(c: Deps) -> dict[str, object]:
    return c.fabric.tokens.jwks()


@router.get("/.well-known/oauth-authorization-server", tags=["discovery"])
async def metadata(c: Deps) -> dict[str, object]:
    issuer = c.settings.issuer_str
    return {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "token_endpoint": f"{issuer}/oauth2/token",
        "introspection_endpoint": f"{issuer}/oauth2/introspect",
        "revocation_endpoint": f"{issuer}/oauth2/revoke",
        "grant_types_supported": [JWT_BEARER, TOKEN_EXCHANGE],
        "token_endpoint_auth_methods_supported": ["none"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
    }


# ------------------------------------------------------------------- registry


@router.post("/v1/agents", status_code=201, tags=["registry"])
async def register_agent(body: RegisterAgent, c: Deps, who: Admin) -> AgentView:
    require_role(who, AdminRole.REGISTRAR)
    agent = await c.fabric.register(body, actor=who.subject)
    c.metrics.lifecycle.labels("register").inc()
    return AgentView.of(agent)


@router.get("/v1/agents", tags=["registry"])
async def list_agents(
    c: Deps,
    who: Admin,
    status: AgentStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AgentList:
    require_role(who, AdminRole.REGISTRAR, AdminRole.SECURITY, AdminRole.AUDITOR)
    agents = await c.fabric.list(status=status, limit=limit, offset=offset)
    return AgentList(items=[AgentView.of(a) for a in agents], limit=limit, offset=offset)


@router.get("/v1/agents/{agent_uri:path}", tags=["registry"])
async def get_agent(agent_uri: str, c: Deps, who: Admin) -> AgentView:
    require_role(who, AdminRole.REGISTRAR, AdminRole.SECURITY, AdminRole.AUDITOR)
    return AgentView.of(await c.fabric.get(agent_uri))


@router.post("/v1/attest", tags=["registry"])
async def attest(
    body: AttestRequest, c: Deps, agent_uri: Annotated[str, Query(min_length=10)]
) -> AgentView:
    """Called by the agent workload itself; authenticated by the workload token."""
    agent = await c.fabric.attest(agent_uri, body.workload_token)
    c.metrics.lifecycle.labels("attest").inc()
    return AgentView.of(agent)


async def _change(
    c: Container, who: AdminPrincipal, uri: str, target: AgentStatus, reason: str
) -> AgentView:
    require_role(who, AdminRole.SECURITY)
    agent = await c.fabric.set_status(uri, target, actor=who.subject, reason=reason)
    c.metrics.lifecycle.labels(target.value).inc()
    return AgentView.of(agent)


@router.post("/v1/suspend", tags=["registry"])
async def suspend(
    body: StatusChange, c: Deps, who: Admin, agent_uri: Annotated[str, Query(min_length=10)]
) -> AgentView:
    return await _change(c, who, agent_uri, AgentStatus.SUSPENDED, body.reason)


@router.post("/v1/reinstate", tags=["registry"])
async def reinstate(
    body: StatusChange, c: Deps, who: Admin, agent_uri: Annotated[str, Query(min_length=10)]
) -> AgentView:
    return await _change(c, who, agent_uri, AgentStatus.ACTIVE, body.reason)


@router.post("/v1/revoke-agent", tags=["registry"])
async def revoke_agent(
    body: StatusChange, c: Deps, who: Admin, agent_uri: Annotated[str, Query(min_length=10)]
) -> AgentView:
    return await _change(c, who, agent_uri, AgentStatus.REVOKED, body.reason)


# --------------------------------------------------------------------- OAuth


@router.post("/oauth2/token", tags=["oauth"])
async def token(
    *,
    c: Deps,
    response: Response,
    grant_type: Annotated[str, Form()],
    scope: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    assertion: Annotated[str | None, Form()] = None,
    subject_token: Annotated[str | None, Form()] = None,
    subject_token_type: Annotated[str | None, Form()] = None,
    actor_token: Annotated[str | None, Form()] = None,
    actor_token_type: Annotated[str | None, Form()] = None,
) -> IssuedToken:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    scopes = frozenset(scope.split()) if scope else None
    try:
        if grant_type == JWT_BEARER:
            if not client_id or not assertion:
                raise InvalidGrantError("client_id and assertion are required")
            issued = await c.fabric.issue_for_workload(client_id, assertion, scopes=scopes)
        elif grant_type == TOKEN_EXCHANGE:
            if not subject_token or not actor_token:
                raise InvalidGrantError("subject_token and actor_token are required")
            if subject_token_type not in JWT_TOKEN_TYPES or actor_token_type not in JWT_TOKEN_TYPES:
                raise InvalidGrantError("unsupported token type")
            try:
                issued = await c.fabric.exchange(subject_token, actor_token, scopes=scopes)
            except UnauthorizedError as exc:
                raise InvalidGrantError(exc.message) from exc
        else:
            c.metrics.token_failures.labels("unknown", "unsupported_grant_type").inc()
            raise FabricError(f"unsupported grant_type {grant_type}")
    except FabricError as exc:
        if grant_type in {JWT_BEARER, TOKEN_EXCHANGE}:
            c.metrics.token_failures.labels(grant_type.rsplit(":", 1)[-1], exc.code).inc()
        raise
    c.metrics.tokens_issued.labels(grant_type.rsplit(":", 1)[-1]).inc()
    return issued


@router.post("/oauth2/introspect", tags=["oauth"], response_model_exclude_none=True)
async def introspect(c: Deps, token: Annotated[str, Form()]) -> Introspection:
    return await c.fabric.introspect(token)


@router.post("/oauth2/revoke", status_code=200, tags=["oauth"])
async def revoke(
    c: Deps, caller: Annotated[str, Depends(bearer)], token: Annotated[str, Form()]
) -> dict[str, str]:
    """A valid agent may revoke tokens; the caller is recorded in the audit trail."""
    claims = await c.fabric.validate(caller)
    await c.fabric.revoke_token(token, actor=claims.sub)
    return {"status": "ok"}


# -------------------------------------------------------------- authorization


@router.post("/v1/authorize", tags=["authorization"])
async def authorize(
    body: AuthorizeRequest, c: Deps, token: Annotated[str, Depends(bearer)]
) -> AuthorizationDecision:
    decision = await c.fabric.authorize(
        token,
        action=body.action,
        resource=Resource(
            type=body.resource_type,
            id=body.resource_id,
            classification=body.resource_classification,
            attributes=body.resource_attributes,
        ),
        environment=body.environment,
    )
    c.metrics.authz_decisions.labels(decision.decision.value).inc()
    return decision


# ----------------------------------------------------------------- operations


@router.get("/healthz", tags=["operations"], include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["operations"], include_in_schema=False)
async def readyz(c: Deps, response: Response) -> dict[str, str]:
    try:
        async with c.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "database unavailable"}
    return {"status": "ready"}


@router.get("/metrics", tags=["operations"], include_in_schema=False)
async def metrics(c: Deps) -> Response:
    return Response(generate_latest(c.metrics.registry), media_type=CONTENT_TYPE_LATEST)
