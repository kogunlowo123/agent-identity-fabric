from __future__ import annotations

import asyncio
import io
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity_fabric.api.app import purge_revocations_forever
from identity_fabric.keygen import generate, main
from identity_fabric.runtime.container import Container


def test_keygen_writes_private_pem_to_stdout_and_jwk_to_stderr() -> None:
    out, err = io.StringIO(), io.StringIO()
    generate("2026-11", out, err)
    key = serialization.load_pem_private_key(out.getvalue().encode(), password=None)
    assert isinstance(key, Ed25519PrivateKey)
    jwk = json.loads(err.getvalue())
    assert jwk["kid"] == "2026-11"
    assert "d" not in jwk  # private component never leaves stdout


def test_keygen_usage() -> None:
    assert main([]) == 2


async def test_purge_loop_updates_gauge_and_survives_errors(container: Container) -> None:
    calls = {"n": 0}

    async def flaky() -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("db hiccup")
        return 3

    container.fabric.purge_revocations = flaky  # type: ignore[method-assign]

    async def stop_after_two(_: float) -> None:
        if calls["n"] >= 2:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await purge_revocations_forever(container, 900, sleep=stop_after_two)
    assert calls["n"] == 2
    assert container.metrics.revocations_purged._value.get() == 3
