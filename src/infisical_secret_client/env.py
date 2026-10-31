"""Process-wide access to an app's secrets: one login per process, not per lookup.

Infisical locks an identity out for minutes after a few failed logins, so apps
must not create a client for every value they need. These helpers load the
bundle (shared + app path) once, keep it in memory and hand out values.

Infisical is optional: without INFISICAL_CLIENT_ID only the environment is used.
"""
from __future__ import annotations

import os
import re
import threading

from .client import InfisicalClient, InfisicalConfig, InfisicalError

_MISSING = object()
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_lock = threading.Lock()
_bundle: dict[str, str] | None = None


def bundle() -> dict[str, str]:
    """All secrets of this app, loaded once. Empty when Infisical is not configured."""
    global _bundle
    with _lock:
        if _bundle is None:
            if os.environ.get("INFISICAL_CLIENT_ID"):
                _bundle = InfisicalClient(InfisicalConfig.from_env()).load_bundle()
            else:
                _bundle = {}
        return _bundle


def secret(name: str, default=_MISSING) -> str:
    """The environment value if set, otherwise the Infisical value.

    Without a default a missing secret raises InfisicalError; the message names
    the key, never a value.
    """
    value = os.environ.get(name)
    if value:
        return value
    value = bundle().get(name)
    if value is not None:
        return value
    if default is _MISSING:
        raise InfisicalError(f"secret niet gevonden: {name}")
    return default


def load_into_environ() -> list[str]:
    """Export the bundle into os.environ, overwriting existing values.

    For apps that read settings from the environment: `.env` is the fallback,
    Infisical the source of truth. Returns the exported names.
    """
    names = []
    for name, value in bundle().items():
        if _ENV_NAME.fullmatch(name):
            os.environ[name] = str(value)
            names.append(name)
    return names


def reset() -> None:
    """Forget the loaded bundle (tests, or after rotating credentials)."""
    global _bundle
    with _lock:
        _bundle = None
