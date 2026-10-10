import base64
import io
import json
import urllib.error

from infisical_secret_client import InfisicalClient, InfisicalConfig
from infisical_secret_client import cli


class Response:
    def __init__(self, payload):
        self.payload = payload
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def read(self):
        return json.dumps(self.payload).encode()


def token():
    claims = base64.urlsafe_b64encode(json.dumps({"orgId": "org"}).encode()).decode().rstrip("=")
    return f"h.{claims}.s"


def config():
    return InfisicalConfig(address="https://vault.test", client_id="id", client_secret="secret",
                           project_id="project", secret_path="/apps/x")


def fake(monkeypatch, routes):
    calls = []
    def open_(request, **_):
        url = request.full_url.split("?")[0].replace("https://vault.test", "")
        body = json.loads(request.data) if request.data and request.get_method() != "POST" or (
            request.data and request.headers.get("Content-type") == "application/json") else None
        calls.append((request.get_method(), url, body))
        if url.endswith("/login"):
            return Response({"accessToken": token()})
        result = routes.get((request.get_method(), url), {})
        if isinstance(result, int):
            raise urllib.error.HTTPError(url, result, "x", {}, None)
        return Response(result)
    monkeypatch.setattr("urllib.request.urlopen", open_)
    return calls


def test_set_updates_existing_secret(monkeypatch):
    calls = fake(monkeypatch, {})
    assert InfisicalClient(config()).set_secret("A", "v") == "updated"
    assert calls[-1][0] == "PATCH" and calls[-1][2]["secretValue"] == "v" and calls[-1][2]["secretPath"] == "/apps/x"


def test_set_creates_missing_secret_and_folders(monkeypatch):
    state = {"posts": 0}
    routes = {("PATCH", "/api/v4/secrets/A"): 404}
    calls = fake(monkeypatch, routes)
    # first POST fails (folder missing), the retry after creating folders succeeds
    routes[("POST", "/api/v4/secrets/A")] = 404
    client = InfisicalClient(config())
    real_api = client._api
    def api(method, path, body=None):
        if (method, path) == ("POST", "/api/v4/secrets/A"):
            state["posts"] += 1
            if state["posts"] == 2:
                routes.pop(("POST", "/api/v4/secrets/A"))
        return real_api(method, path, body)
    client._api = api
    assert client.set_secret("A", "v") == "created"
    created = [c[2]["name"] for c in calls if c[:2] == ("POST", "/api/v1/folders")]
    assert created == ["apps", "x"]


def test_identity_gets_read_privilege_on_paths(monkeypatch):
    calls = fake(monkeypatch, {
        ("GET", "/api/v2/organizations/org/identity-memberships"): {"identityMemberships": []},
        ("POST", "/api/v1/identities"): {"identity": {"id": "i1"}},
        ("POST", "/api/v1/auth/universal-auth/identities/i1"): {"identityUniversalAuth": {"clientId": "cid"}},
        ("POST", "/api/v1/auth/universal-auth/identities/i1/client-secrets"): {"clientSecret": "cs"},
    })
    client = InfisicalClient(config())
    identity = client.ensure_app_identity("app-x", read_paths=["/shared", "/apps/x"])
    assert identity == {"identityId": "i1", "clientId": "cid", "clientSecret": "cs", "created": True}
    privilege = next(c[2] for c in calls if c[1] == "/api/v2/identity-project-additional-privilege")
    globs = sorted(r["conditions"]["secretPath"]["$glob"] for r in privilege["permissions"])
    assert globs == ["/apps/x", "/apps/x/**", "/shared", "/shared/**"]
    assert all(r["action"] == ["read", "describeSecret", "readValue"] for r in privilege["permissions"])
    env = client.bootstrap_env(identity, secret_path="/apps/x", shared_path="/shared")
    assert "INFISICAL_CLIENT_SECRET=cs\n" in env and "INFISICAL_SECRET_PATH=/apps/x\n" in env


def test_cli_set_reads_value_from_stdin(monkeypatch, capsys):
    calls = fake(monkeypatch, {})
    for k, v in {"INFISICAL_ADDR": "https://vault.test", "INFISICAL_CLIENT_ID": "id",
                 "INFISICAL_CLIENT_SECRET": "s", "INFISICAL_PROJECT_ID": "project"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr("sys.stdin", io.StringIO("geheim\n"))
    assert cli.main(["--path", "/apps/x", "set", "A"]) == 0
    assert calls[-1][2]["secretValue"] == "geheim"
    assert "geheim" not in capsys.readouterr().out
