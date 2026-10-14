"""Workload attestation.

An agent proves which workload it runs as by presenting a token minted by
the workload platform: a Kubernetes projected service-account token, an
EKS/GKE/AKS workload identity token, or a SPIFFE JWT-SVID. The fabric
verifies the token against the issuer's JWKS and checks it matches the
workload binding recorded at registration. Optionally the running image
digest (reported by an admission controller into a signed claim) must be on
the registration's allow list.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from identity_fabric.domain.errors import AttestationError, UnauthorizedError
from identity_fabric.domain.models import Agent
from identity_fabric.security.jwks import KeyResolver, verify_jwt


class AttestationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    issuer: str
    subject: str
    image_digest: str | None
    token_id: str | None


class WorkloadAttestor:
    def __init__(self, resolvers: Mapping[str, KeyResolver]) -> None:
        """``resolvers`` maps each trusted workload issuer URL to its key resolver."""
        self._resolvers = dict(resolvers)

    def trusts(self, issuer: str) -> bool:
        return issuer in self._resolvers

    async def attest(self, agent: Agent, workload_token: str) -> AttestationResult:
        binding = agent.workload
        resolver = self._resolvers.get(binding.issuer)
        if resolver is None:
            raise AttestationError(f"workload issuer {binding.issuer} is not trusted")
        try:
            claims = await verify_jwt(
                workload_token, resolver, issuer=binding.issuer, audience=binding.audience
            )
        except UnauthorizedError as exc:
            raise AttestationError(f"workload token invalid: {exc.message}") from exc

        if claims.get("sub") != binding.subject:
            raise AttestationError("workload subject does not match registration")
        digest = _image_digest(claims)
        if binding.image_digests and digest not in binding.image_digests:
            raise AttestationError("workload image digest is not on the allow list")
        jti = claims.get("jti")
        return AttestationResult(
            issuer=binding.issuer,
            subject=binding.subject,
            image_digest=digest,
            token_id=jti if isinstance(jti, str) else None,
        )


def _image_digest(claims: Mapping[str, Any]) -> str | None:
    value = claims.get("image_digest")
    if isinstance(value, str):
        return value
    k8s = claims.get("kubernetes.io")
    if isinstance(k8s, Mapping):
        pod = k8s.get("pod")
        if isinstance(pod, Mapping) and isinstance(pod.get("image_digest"), str):
            return str(pod["image_digest"])
    return None
