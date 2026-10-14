"""Ed25519 signing key ring with rotation and JWKS publication.

Keys are PEM files named ``<kid>.pem`` in a directory mounted from the
platform secret store. The active signing key is the one named by
``active_kid``; every other key in the directory stays published in the JWKS
so tokens signed before a rotation still verify until they expire.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def jwk(self) -> dict[str, str]:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(raw),
            "kid": self.kid,
            "use": "sig",
            "alg": "EdDSA",
        }

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


class KeyRing:
    def __init__(self, keys: list[SigningKey], *, active_kid: str) -> None:
        if not keys:
            raise ValueError("key ring is empty")
        self._keys = {k.kid: k for k in keys}
        if len(self._keys) != len(keys):
            raise ValueError("duplicate key ids")
        if active_kid not in self._keys:
            raise ValueError(f"active kid {active_kid!r} not present")
        self._active = active_kid

    @classmethod
    def from_directory(cls, directory: Path, *, active_kid: str) -> KeyRing:
        keys: list[SigningKey] = []
        for path in sorted(directory.glob("*.pem")):
            loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ValueError(f"{path.name}: only Ed25519 signing keys are supported")
            keys.append(SigningKey(kid=path.stem, private_key=loaded))
        return cls(keys, active_kid=active_kid)

    @classmethod
    def ephemeral(cls, kid: str = "ephemeral") -> KeyRing:
        """In-memory key for local development and tests; never persisted."""
        return cls([SigningKey(kid=kid, private_key=Ed25519PrivateKey.generate())], active_kid=kid)

    @property
    def active(self) -> SigningKey:
        return self._keys[self._active]

    def public_key(self, kid: str) -> Ed25519PublicKey | None:
        key = self._keys.get(kid)
        return key.public_key if key else None

    def jwks(self) -> dict[str, Any]:
        return {"keys": [k.jwk() for k in self._keys.values()]}
