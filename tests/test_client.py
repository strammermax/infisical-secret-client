import json
import urllib.error
import urllib.parse

import pytest

from infisical_secret_client import InfisicalClient, InfisicalConfig, InfisicalError


class Response:
    def __init__(self, payload):
        self.payload = payload
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def read(self):
        return json.dumps(self.payload).encode()


def config(**overrides):
    values = dict(address="https://vault.test", client_id="id", client_secret="secret",
                  project_id="project", environment="production", secret_path="/Prefect",
                  shared_path="/shared")
    values.update(overrides)
    return InfisicalConfig(**values)


def test_login_and_list_do_not_put_credentials_in_url(monkeypatch):
    requests = []
    def fake_open(request, **_):
        requests.append(request)
        if request.full_url.endswith("/login"):
            return Response({"accessToken": "short-lived"})
        return Response({"secrets": [{"secretKey": "A", "secretValue": "value"}]})
    monkeypatch.setattr("urllib.request.urlopen", fake_open)

    assert InfisicalClient(config()).list_secrets() == {"A": "value"}
    assert "secret" not in requests[0].full_url
    assert requests[1].headers["Authorization"] == "Bearer short-lived"


def test_plain_http_requires_explicit_opt_in():
    with pytest.raises(InfisicalError, match="HTTP geweigerd"):
        InfisicalClient(config(address="http://vault.test"))
    InfisicalClient(config(address="http://vault.test", allow_http=True))


def test_http_error_is_redacted(monkeypatch):
    def fail(*_args, **_kwargs):
        raise urllib.error.HTTPError("https://vault", 401, "bad", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", fail)
    client = InfisicalClient(config(client_secret="must-not-leak"))
    with pytest.raises(InfisicalError) as caught:
        client.login()
    assert "must-not-leak" not in str(caught.value)


def test_bundle_uses_one_login_and_app_overrides_shared(monkeypatch):
    requests = []
    def fake_open(request, **_):
        requests.append(request)
        if request.full_url.endswith("/login"):
            return Response({"accessToken": "short-lived"})
        query = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)
        if query["secretPath"] == ["/shared"]:
            return Response({"secrets": [
                {"secretKey": "COMMON", "secretValue": "shared"},
                {"secretKey": "ONLY_SHARED", "secretValue": "yes"},
            ]})
        return Response({"secrets": [
            {"secretKey": "COMMON", "secretValue": "app"},
            {"secretKey": "APP_KEY", "secretValue": "value"},
        ]})
    monkeypatch.setattr("urllib.request.urlopen", fake_open)

    result = InfisicalClient(config()).load_bundle()

    assert result == {"COMMON": "app", "ONLY_SHARED": "yes", "APP_KEY": "value"}
    assert len([r for r in requests if r.full_url.endswith("/login")]) == 1


def test_shared_folder_is_optional(monkeypatch):
    requests = []
    def fake_open(request, **_):
        requests.append(request)
        if request.full_url.endswith("/login"):
            return Response({"accessToken": "short-lived"})
        return Response({"secrets": [{"secretKey": "APP_KEY", "secretValue": "value"}]})
    monkeypatch.setattr("urllib.request.urlopen", fake_open)

    result = InfisicalClient(config(shared_path=None)).load_bundle()

    assert result == {"APP_KEY": "value"}
    assert len(requests) == 2  # one login and one app-folder request
