"""Generate an Ed25519 signing or audit key for upload to the cloud secret manager.

The key is written to stdout only, so it can be piped straight into the
secret manager without touching disk:

    python -m identity_fabric.keygen | aws secretsmanager create-secret \
        --name agent-identity-fabric-signing-key-2026-11 --kms-key-id <arn> \
        --secret-string file:///dev/stdin

The public JWK is written to stderr for the change record.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity_fabric.security.keys import SigningKey


def generate(kid: str, out: TextIO, err: TextIO) -> None:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    out.write(pem)
    err.write(json.dumps(SigningKey(kid=kid, private_key=key).jwk()) + "\n")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        sys.stderr.write("usage: python -m identity_fabric.keygen <kid>\n")
        return 2
    generate(args[0], sys.stdout, sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
