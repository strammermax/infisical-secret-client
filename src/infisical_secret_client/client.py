"""Dependency-free Infisical Universal Auth and secrets client."""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


class InfisicalError(RuntimeError):
    """A safe error that never contains credentials or secret values."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class InfisicalConfig:
    address: str
    client_id: str
    client_secret: str
    project_id: str
    environment: str = "prod"
    secret_path: str = "/"
    shared_path: str | None = None
    allow_http: bool = False
    ca_bundle: str | None = None
    timeout_seconds: int = 15

    @classmethod
    def from_env(cls) -> "InfisicalConfig":
        def required(name: str) -> str:
            value = os.environ.get(name, "").strip()
            if not value:
                raise InfisicalError(f"verplichte omgevingsvariabele ontbreekt: {name}")
            return value

        return cls(
            address=required("INFISICAL_ADDR"),
            client_id=required("INFISICAL_CLIENT_ID"),
            client_secret=required("INFISICAL_CLIENT_SECRET"),
            project_id=required("INFISICAL_PROJECT_ID"),
            environment=os.environ.get("INFISICAL_ENVIRONMENT", "prod"),
            secret_path=os.environ.get("INFISICAL_SECRET_PATH", "/"),
            shared_path=os.environ.get("INFISICAL_SHARED_PATH") or None,
            allow_http=os.environ.get("INFISICAL_ALLOW_HTTP", "false").lower() in {"1", "true", "yes"},
            ca_bundle=os.environ.get("INFISICAL_CA_BUNDLE") or None,
            timeout_seconds=int(os.environ.get("INFISICAL_TIMEOUT_SECONDS", "15")),
        )


class InfisicalClient:
    def __init__(self, config: InfisicalConfig):
        self.config = config
        self.base_url = config.address.rstrip("/")
        scheme = urllib.parse.urlparse(self.base_url).scheme
        if scheme not in {"http", "https"}:
            raise InfisicalError("INFISICAL_ADDR moet met http:// of https:// beginnen")
        if scheme == "http" and not config.allow_http:
            raise InfisicalError("onversleuteld HTTP geweigerd; gebruik HTTPS of zet INFISICAL_ALLOW_HTTP=true")
        self._ssl_context = ssl.create_default_context(cafile=config.ca_bundle)
        self._access_token: str | None = None

    def _request(self, path: str, *, data: bytes | None = None,
                 headers: dict[str, str] | None = None) -> dict:
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(
                request, timeout=self.config.timeout_seconds,
                context=self._ssl_context if self.base_url.startswith("https://") else None,
            ) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise InfisicalError(
                f"Infisical gaf HTTP {exc.code} voor {path.split('?')[0]}",
                status_code=exc.code,
            ) from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise InfisicalError(f"Infisical is niet bereikbaar of gaf een ongeldig antwoord: {type(exc).__name__}") from None

    def login(self) -> str:
        if self._access_token:
            return self._access_token
        body = urllib.parse.urlencode({
            "clientId": self.config.client_id,
            "clientSecret": self.config.client_secret,
        }).encode()
        payload = self._request(
            "/api/v1/auth/universal-auth/login", data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token = payload.get("accessToken")
        if not token:
            raise InfisicalError("Infisical-login bevatte geen accessToken")
        self._access_token = token
        return token

    def list_secrets(self, *, secret_path: str | None = None,
                     environment: str | None = None, recursive: bool = False) -> dict[str, str]:
        token = self.login()
        query = urllib.parse.urlencode({
            "projectId": self.config.project_id,
            "environment": environment or self.config.environment,
            "secretPath": secret_path or self.config.secret_path,
            "viewSecretValue": "true",
            "expandSecretReferences": "true",
            "recursive": str(recursive).lower(),
        })
        headers = {"Authorization": f"Bearer {token}"}
        try:
            payload = self._request(f"/api/v4/secrets?{query}", headers=headers)
        except InfisicalError as exc:
            # Older self-hosted releases expose the same operation on the
            # deprecated v3 route. Fall back only when v4 itself is absent;
            # authorization and validation failures must remain visible.
            if exc.status_code != 404:
                raise
            legacy_query = urllib.parse.urlencode({
                "workspaceId": self.config.project_id,
                "environment": environment or self.config.environment,
                "secretPath": secret_path or self.config.secret_path,
                "viewSecretValue": "true",
                "expandSecretReferences": "true",
                "recursive": str(recursive).lower(),
            })
            payload = self._request(
                f"/api/v3/secrets/raw?{legacy_query}", headers=headers,
            )
        return {
            item["secretKey"]: item["secretValue"]
            for item in payload.get("secrets", [])
            if "secretKey" in item and "secretValue" in item
        }

    def get_secret(self, name: str, *, secret_path: str | None = None,
                   environment: str | None = None) -> str:
        secrets = self.list_secrets(secret_path=secret_path, environment=environment)
        if name not in secrets:
            raise InfisicalError(f"secret niet gevonden: {name}")
        return secrets[name]

    def load_bundle(self, *, app_path: str | None = None,
                    shared_path: str | None = None,
                    environment: str | None = None,
                    recursive: bool = True) -> dict[str, str]:
        """Load shared and app secrets with one login and return one environment.

        Shared values are loaded first. App-specific values deliberately override
        keys with the same name, allowing safe shared defaults.
        """
        application = app_path or self.config.secret_path
        shared = self.config.shared_path if shared_path is None else shared_path
        result: dict[str, str] = {}
        if shared and shared != application:
            result.update(self.list_secrets(
                secret_path=shared, environment=environment, recursive=recursive,
            ))
        result.update(self.list_secrets(
            secret_path=application, environment=environment, recursive=recursive,
        ))
        return result
