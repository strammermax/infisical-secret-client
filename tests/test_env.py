import os

import pytest

from infisical_secret_client import InfisicalError, env


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    env.reset()
    for name in ("INFISICAL_CLIENT_ID", "FROM_ENV", "FROM_VAULT", "BOTH"):
        monkeypatch.delenv(name, raising=False)
    yield
    env.reset()


@pytest.fixture
def vault(monkeypatch):
    calls = []

    class FakeClient:
        def __init__(self, config):
            calls.append(config)

        def load_bundle(self):
            return {"FROM_VAULT": "vault", "BOTH": "vault", "not-a-name": "x"}

    monkeypatch.setenv("INFISICAL_CLIENT_ID", "id")
    monkeypatch.setattr(env, "InfisicalClient", FakeClient)
    monkeypatch.setattr(env.InfisicalConfig, "from_env", classmethod(lambda cls: "config"))
    return calls


def test_one_login_for_many_lookups(vault):
    for _ in range(3):
        assert env.secret("FROM_VAULT") == "vault"
    assert len(vault) == 1


def test_environment_wins_for_secret(vault, monkeypatch):
    monkeypatch.setenv("BOTH", "env")
    assert env.secret("BOTH") == "env"


def test_missing_secret_raises_without_default_and_returns_default(vault):
    with pytest.raises(InfisicalError, match="NOPE"):
        env.secret("NOPE")
    assert env.secret("NOPE", None) is None


def test_without_infisical_only_environment(monkeypatch):
    monkeypatch.setenv("FROM_ENV", "env")
    assert env.bundle() == {}
    assert env.secret("FROM_ENV") == "env"
    assert env.load_into_environ() == []


def test_load_into_environ_overwrites_and_skips_invalid_names(vault, monkeypatch):
    monkeypatch.setenv("BOTH", "env")
    assert sorted(env.load_into_environ()) == ["BOTH", "FROM_VAULT"]
    assert os.environ["BOTH"] == "vault"
    assert "not-a-name" not in os.environ
