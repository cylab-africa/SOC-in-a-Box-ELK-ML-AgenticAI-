"""Tests for es_tls: Elasticsearch TLS verification and login settings."""

from __future__ import annotations

from pathlib import Path

import pytest

import es_tls
from es_tls import diagnose_connection_failure, es_auth_kwargs, es_tls_kwargs, tls_failure_hint


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test with no TLS environment overrides."""
    monkeypatch.delenv("ES_VERIFY_CERTS", raising=False)
    monkeypatch.delenv("ES_CA_CERT", raising=False)
    for name in ("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(es_tls, "_insecure_warning_logged", False)


def test_verifies_by_default() -> None:
    """With nothing configured, certificates are verified."""
    assert es_tls_kwargs() == {"verify_certs": True}


@pytest.mark.parametrize("value", ["false", "False", "0", "no", "off"])
def test_env_can_disable_verification(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """ES_VERIFY_CERTS=false (and its spellings) turns verification off."""
    monkeypatch.setenv("ES_VERIFY_CERTS", value)
    assert es_tls_kwargs() == {"verify_certs": False, "ssl_show_warn": False}


@pytest.mark.parametrize("value", ["true", "1", "yes", ""])
def test_env_truthy_or_empty_keeps_verification(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """Anything other than an explicit false keeps verification on."""
    monkeypatch.setenv("ES_VERIFY_CERTS", value)
    assert es_tls_kwargs()["verify_certs"] is True


def test_disabling_logs_one_warning(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    """The insecure-mode warning is logged once per process, not per client."""
    monkeypatch.setenv("ES_VERIFY_CERTS", "false")
    with caplog.at_level("WARNING", logger="linux_anomaly_detection"):
        es_tls_kwargs()
        es_tls_kwargs()
    assert sum("verification is disabled" in r.message for r in caplog.records) == 1


def test_ca_cert_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """ES_CA_CERT is passed through as ca_certs."""
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setenv("ES_CA_CERT", str(ca))
    assert es_tls_kwargs() == {"verify_certs": True, "ca_certs": str(ca)}


def test_missing_ca_cert_fails_loudly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A CA path that does not exist is a configuration error, not a silent fallback."""
    monkeypatch.setenv("ES_CA_CERT", str(tmp_path / "missing.pem"))
    with pytest.raises(FileNotFoundError, match="ES_CA_CERT"):
        es_tls_kwargs()


def test_explicit_arguments_override_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Config values passed in win over the environment."""
    monkeypatch.setenv("ES_VERIFY_CERTS", "false")
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    assert es_tls_kwargs(True, str(ca)) == {"verify_certs": True, "ca_certs": str(ca)}
    monkeypatch.delenv("ES_VERIFY_CERTS")
    assert es_tls_kwargs(False)["verify_certs"] is False


def test_tls_failure_hint_recognises_cert_errors() -> None:
    """Certificate failures get an actionable hint; other errors do not."""
    err = ConnectionError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate in certificate chain")
    assert "ES_CA_CERT" in (tls_failure_hint(err) or "")
    assert tls_failure_hint(ConnectionError("Connection refused")) is None


def test_diagnose_connection_failure() -> None:
    """The diagnosis repeats one request and inspects its error."""

    class FailingClient:
        def info(self) -> None:
            raise ConnectionError("certificate verify failed: unable to get local issuer certificate")

    class HealthyClient:
        def info(self) -> dict[str, str]:
            return {"cluster_name": "test"}

    assert "ES_CA_CERT" in (diagnose_connection_failure(FailingClient()) or "")
    assert diagnose_connection_failure(HealthyClient()) is None


def test_elasticsearch_config_defaults_to_verification() -> None:
    """The elasticsearch config section verifies certificates unless told otherwise."""
    from config import ElasticsearchConfig

    assert ElasticsearchConfig().verify_certs is True
    assert ElasticsearchConfig().ca_certs == ""


def test_auth_api_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """ES_API_KEY is passed through as api_key."""
    monkeypatch.setenv("ES_API_KEY", " test-api-key ")
    assert es_auth_kwargs() == {"api_key": "test-api-key"}


def test_auth_username_password_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without an API key, ES_USERNAME and ES_PASSWORD become basic_auth."""
    monkeypatch.setenv("ES_USERNAME", "analyst")
    monkeypatch.setenv("ES_PASSWORD", "secret")
    assert es_auth_kwargs() == {"basic_auth": ("analyst", "secret")}


def test_auth_api_key_wins_over_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """When both are configured, the scoped API key is used."""
    monkeypatch.setenv("ES_API_KEY", "test-api-key")
    monkeypatch.setenv("ES_USERNAME", "elastic")
    monkeypatch.setenv("ES_PASSWORD", "secret")
    assert es_auth_kwargs() == {"api_key": "test-api-key"}


def test_auth_explicit_arguments_win(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit arguments override the environment; an empty string means unset."""
    monkeypatch.setenv("ES_API_KEY", "from-env")
    assert es_auth_kwargs("", "analyst", "secret") == {"basic_auth": ("analyst", "secret")}


def test_auth_nothing_configured() -> None:
    """No login, or a username without a password, gives no auth arguments."""
    assert es_auth_kwargs() == {}
    assert es_auth_kwargs(username="analyst") == {}


def test_engine_client_uses_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The detection engine's client logs in with the API key from its config."""
    import datamanager

    captured: dict = {}

    class FakeElasticsearch:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def ping(self) -> bool:
            return True

        def info(self) -> dict[str, dict[str, str]]:
            return {"version": {"number": "8.15.0"}}

    monkeypatch.setattr(datamanager, "Elasticsearch", FakeElasticsearch)
    config = {"elasticsearch": {"host": "https://es:9200", "api_key": "test-api-key",
                                "username": "elastic", "password": "secret"}}
    datamanager.connect_to_elasticsearch(config)
    assert captured["api_key"] == "test-api-key"
    assert "basic_auth" not in captured and "http_auth" not in captured
