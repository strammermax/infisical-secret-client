"""Dependency-free Infisical Universal Auth, secrets and identity client."""
from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace

# Actions a read-only identity needs to list names and read values.
# "read" is a legacy action; current Infisical rejects it next to
# describeSecret/readValue (HTTP 400), so only the current actions are used.
READ_ACTIONS = ["describeSecret", "readValue"]
WRITE_ACTIONS = ["create", "edit", "delete"]


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
    def from_env(cls, *, admin: bool = False) -> "InfisicalConfig":
        """Reads the bootstrap from the environment.

        With admin=True the separate INFISICAL_ADMIN_CLIENT_ID/SECRET are used:
        an identity that may manage folders, identities and permissions. Apps
        only ever get the normal, read-only credentials.
        """
        def required(name: str) -> str:
            value = os.environ.get(name, "").strip()
            if not value:
                raise InfisicalError(f"verplichte omgevingsvariabele ontbreekt: {name}")
            return value

        prefix = "INFISICAL_ADMIN_" if admin else "INFISICAL_"
        return cls(
            address=required("INFISICAL_ADDR"),
            client_id=required(prefix + "CLIENT_ID"),
            client_secret=required(prefix + "CLIENT_SECRET"),
            project_id=required("INFISICAL_PROJECT_ID"),
            environment=os.environ.get("INFISICAL_ENVIRONMENT", "prod"),
            secret_path=os.environ.get("INFISICAL_SECRET_PATH", "/"),
            shared_path=os.environ.get("INFISICAL_SHARED_PATH") or None,
            allow_http=os.environ.get("INFISICAL_ALLOW_HTTP", "false").lower() in {"1", "true", "yes"},
            ca_bundle=os.environ.get("INFISICAL_CA_BUNDLE") or None,
            timeout_seconds=int(os.environ.get("INFISICAL_TIMEOUT_SECONDS", "15")),
        )


def _normalize_path(path: str) -> str:
    parts = [part for part in (path or "/").split("/") if part]
    return "/" + "/".join(parts)


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
                 headers: dict[str, str] | None = None, method: str | None = None) -> dict:
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers or {}, method=method)
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

    def _api(self, method: str, path: str, body: dict | None = None) -> dict:
        headers = {"Authorization": f"Bearer {self.login()}"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        return self._request(path, data=data, headers=headers, method=method)

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
        keys with the same name, allowing safe shared defaults. `shared_path` may
        hold several folders, comma-separated, loaded in that order.
        """
        application = app_path or self.config.secret_path
        shared = self.config.shared_path if shared_path is None else shared_path
        result: dict[str, str] = {}
        for folder in [part.strip() for part in (shared or "").split(",") if part.strip()]:
            if folder != application:
                result.update(self.list_secrets(
                    secret_path=folder, environment=environment, recursive=recursive,
                ))
        result.update(self.list_secrets(
            secret_path=application, environment=environment, recursive=recursive,
        ))
        return result

    # -- writing -----------------------------------------------------------------

    def ensure_folder(self, path: str, *, environment: str | None = None) -> None:
        """Create every missing folder in `path` (no-op for "/")."""
        env = environment or self.config.environment
        parent = "/"
        for name in [part for part in _normalize_path(path).split("/") if part]:
            query = urllib.parse.urlencode({"workspaceId": self.config.project_id, "environment": env, "path": parent})
            existing = {folder.get("name") for folder in self._api("GET", f"/api/v1/folders?{query}").get("folders", [])}
            if name not in existing:
                self._api("POST", "/api/v1/folders", {"workspaceId": self.config.project_id, "environment": env,
                                                      "name": name, "path": parent})
            parent = _normalize_path(parent + "/" + name)

    def set_secret(self, name: str, value: str, *, secret_path: str | None = None,
                   environment: str | None = None, create_folders: bool = True) -> str:
        """Create or update one secret. Returns "created" or "updated"."""
        path = _normalize_path(secret_path or self.config.secret_path)
        body = {"projectId": self.config.project_id, "environment": environment or self.config.environment,
                "secretPath": path, "secretValue": value}
        quoted = urllib.parse.quote(name, safe="")
        try:
            self._api("PATCH", f"/api/v4/secrets/{quoted}", body)
            return "updated"
        except InfisicalError as exc:
            if exc.status_code not in (400, 404):
                raise
        try:
            self._api("POST", f"/api/v4/secrets/{quoted}", body)
        except InfisicalError as exc:
            if not create_folders or exc.status_code not in (400, 404):
                raise
            self.ensure_folder(path, environment=environment)
            self._api("POST", f"/api/v4/secrets/{quoted}", body)
        return "created"

    def delete_secret(self, name: str, *, secret_path: str | None = None,
                      environment: str | None = None) -> None:
        body = {"projectId": self.config.project_id, "environment": environment or self.config.environment,
                "secretPath": _normalize_path(secret_path or self.config.secret_path)}
        self._api("DELETE", f"/api/v4/secrets/{urllib.parse.quote(name, safe='')}", body)

    # -- identities (admin credentials) -----------------------------------------

    def organization_id(self) -> str:
        """The organization of the logged-in identity (from its access token)."""
        token = self.login()
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except (IndexError, ValueError):
            raise InfisicalError("organisatie niet te bepalen uit het toegangstoken") from None
        org = claims.get("orgId") or claims.get("organizationId")
        if not isinstance(org, str) or not org:
            raise InfisicalError("organisatie niet te bepalen uit het toegangstoken")
        return org

    def find_identity(self, name: str) -> str | None:
        memberships = self._api("GET", f"/api/v2/organizations/{self.organization_id()}/identity-memberships")
        for membership in memberships.get("identityMemberships", []):
            identity = membership.get("identity") or {}
            if identity.get("name") == name:
                return identity.get("id")
        return None

    def ensure_app_identity(self, name: str, *, read_paths: list[str], write_paths: list[str] | None = None,
                            environment: str | None = None, secret_description: str = "infisical-secret-client") -> dict:
        """An identity that may only read `read_paths` (and write `write_paths`).

        Creates what is missing, adds a fresh Universal Auth client secret and
        returns {"identityId", "clientId", "clientSecret", "created"}. The caller
        stores the secret; it is never logged.
        """
        env = environment or self.config.environment
        identity_id = self.find_identity(name)
        created = identity_id is None
        if created:
            identity = self._api("POST", "/api/v1/identities",
                                 {"name": name, "organizationId": self.organization_id(), "role": "no-access"})
            identity_id = (identity.get("identity") or identity).get("id")
            if not identity_id:
                raise InfisicalError("Infisical gaf geen identiteits-id terug")
        try:
            auth = self._api("POST", f"/api/v1/auth/universal-auth/identities/{identity_id}", {})
        except InfisicalError as exc:
            if exc.status_code != 400:  # already attached
                raise
            auth = self._api("GET", f"/api/v1/auth/universal-auth/identities/{identity_id}")
        client_id = (auth.get("identityUniversalAuth") or auth).get("clientId")
        if not client_id:
            raise InfisicalError("Infisical gaf geen client-id terug")
        secret = self._api("POST", f"/api/v1/auth/universal-auth/identities/{identity_id}/client-secrets",
                           {"description": secret_description}).get("clientSecret")
        if not secret:
            raise InfisicalError("Infisical gaf geen client secret terug")
        try:
            self._api("POST", f"/api/v1/projects/{self.config.project_id}/identity-memberships/{identity_id}",
                      {"role": "no-access"})
        except InfisicalError as exc:
            if exc.status_code != 400:  # already a member
                raise
        self.grant(identity_id, name, read_paths, READ_ACTIONS, env, "read")
        if write_paths:
            self.grant(identity_id, name, write_paths, READ_ACTIONS + WRITE_ACTIONS, env, "write")
        return {"identityId": identity_id, "clientId": client_id, "clientSecret": secret, "created": created}

    def grant(self, identity_id: str, name: str, paths: list[str], actions: list[str], environment: str, kind: str) -> None:
        """Permanent privilege on exactly these folders and their subfolders."""
        rules = []
        for path in paths:
            folder = _normalize_path(path)
            for pattern in {folder, folder.rstrip("/") + "/**"}:
                rules.append({"subject": "secrets", "action": actions,
                              "conditions": {"environment": environment, "secretPath": {"$glob": pattern}}})
        slug = f"{name}-{kind}"[:60].lower().replace("_", "-")
        body = {"identityId": identity_id, "projectId": self.config.project_id, "slug": slug,
                "permissions": rules, "type": {"isTemporary": False}}
        # Look up first: a 400 on create also means "invalid request", so it must
        # not be read as "already exists".
        query = urllib.parse.urlencode({"identityId": identity_id, "projectId": self.config.project_id})
        existing = self._api("GET", f"/api/v2/identity-project-additional-privilege?{query}").get("privileges") or []
        match = next((p for p in existing if p.get("slug") == slug), None)
        if match and match.get("id"):
            self._api("PATCH", f"/api/v2/identity-project-additional-privilege/{match['id']}",
                      {"permissions": rules, "type": {"isTemporary": False}})
        else:
            self._api("POST", "/api/v2/identity-project-additional-privilege", body)

    def bootstrap_env(self, identity: dict, *, secret_path: str, shared_path: str | None = None) -> str:
        """Bootstrap file content for an app using `identity` (contains its secret)."""
        lines = {
            "INFISICAL_ADDR": self.base_url,
            "INFISICAL_CLIENT_ID": identity["clientId"],
            "INFISICAL_CLIENT_SECRET": identity["clientSecret"],
            "INFISICAL_PROJECT_ID": self.config.project_id,
            "INFISICAL_ENVIRONMENT": self.config.environment,
            "INFISICAL_SECRET_PATH": _normalize_path(secret_path),
        }
        if shared_path:
            lines["INFISICAL_SHARED_PATH"] = shared_path
        if self.config.ca_bundle:
            lines["INFISICAL_CA_BUNDLE"] = self.config.ca_bundle
        if self.config.allow_http:
            lines["INFISICAL_ALLOW_HTTP"] = "true"
        return "".join(f"{key}={value}\n" for key, value in lines.items())


def admin_client() -> InfisicalClient:
    """Client with the admin credentials, for folders, identities and permissions."""
    return InfisicalClient(InfisicalConfig.from_env(admin=True))


__all__ = ["InfisicalClient", "InfisicalConfig", "InfisicalError", "admin_client", "replace"]
