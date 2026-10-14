"""Domain errors mapped to HTTP status codes by the API layer."""

from __future__ import annotations


class FabricError(Exception):
    code = "fabric_error"
    status = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(FabricError):
    code = "not_found"
    status = 404


class ConflictError(FabricError):
    code = "conflict"
    status = 409


class InvalidStateError(FabricError):
    code = "invalid_state"
    status = 409


class AttestationError(FabricError):
    code = "attestation_failed"
    status = 401


class InvalidGrantError(FabricError):
    """OAuth 2.0 invalid_grant (RFC 6749 section 5.2)."""

    code = "invalid_grant"
    status = 400


class InvalidScopeError(FabricError):
    code = "invalid_scope"
    status = 400


class UnauthorizedError(FabricError):
    code = "unauthorized"
    status = 401


class ForbiddenError(FabricError):
    code = "forbidden"
    status = 403
