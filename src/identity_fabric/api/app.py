"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from agentic_core.observability import bind_correlation_id, get_logger
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from identity_fabric import __version__
from identity_fabric.api.routes import router
from identity_fabric.domain.errors import FabricError
from identity_fabric.runtime.container import Container

ContainerFactory = Callable[[], Awaitable[Container]]

log = get_logger("identity_fabric.api")


async def purge_revocations_forever(
    container: Container,
    interval_s: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Drop revocation entries whose tokens have expired anyway."""
    while True:
        try:
            removed = await container.fabric.purge_revocations()
            container.metrics.revocations_purged.set(removed)
        except Exception:
            log.exception("revocation_purge_failed")
        await sleep(interval_s)


def create_app(factory: ContainerFactory, *, purge_interval_s: float = 900.0) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await factory()
        app.state.container = container
        sweeper = asyncio.create_task(purge_revocations_forever(container, purge_interval_s))
        log.info("startup", version=__version__)
        try:
            yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            await container.aclose()

    app = FastAPI(
        title="Agent Identity Fabric",
        version=__version__,
        description=(
            "Registration, workload attestation, short-lived credentials, delegation, "
            "authorization and revocation for enterprise AI agents."
        ),
        lifespan=lifespan,
    )
    app.include_router(router)

    @app.middleware("http")
    async def correlation_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-correlation-id")
        cid = incoming if incoming and len(incoming) <= 64 and incoming.isprintable() else None
        started = time.perf_counter()
        with bind_correlation_id(cid) as bound:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = bound
        response.headers["X-Content-Type-Options"] = "nosniff"
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")
        container: Container | None = getattr(request.app.state, "container", None)
        if container is not None:
            container.metrics.requests.labels(
                request.method, path, str(response.status_code)
            ).observe(time.perf_counter() - started)
        return response

    @app.exception_handler(FabricError)
    async def fabric_error(_: Request, exc: FabricError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return JSONResponse(
            status_code=exc.status,
            content={"error": exc.code, "error_description": exc.message},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request",
                "error_description": "request failed validation",
                "details": [
                    {"loc": list(e.get("loc", ())), "msg": str(e.get("msg", ""))}
                    for e in exc.errors()
                ],
            },
        )

    return app
