"""Tests for es_tls: Elasticsearch TLS verification defaults and overrides."""

from __future__ import annotations

from pathlib import Path

import pytest

import es_tls
from es_tls import diagnose_connection_failure, es_tls_kwargs, tls_failure_hint


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every test with no TLS environment overrides."""
    monkeypatch.delenv("ES_VERIFY_CERTS", raising=False)
    monkeypatch.delenv("ES_CA_CERT", raising=False)
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
