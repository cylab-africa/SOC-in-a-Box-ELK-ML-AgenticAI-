"""TLS settings shared by every Elasticsearch client in the pipeline.

Certificate verification is on by default. Two environment variables control it:

- ``ES_CA_CERT``: path to the CA that signed the cluster's HTTP certificate
  (for a self-managed cluster, the node's ``config/certs/http_ca.crt``).
  Relative paths resolve against the working directory, so
  ``config/certs/ca.pem`` works both on the host and in the Docker image,
  where ``config/`` is bind-mounted.
- ``ES_VERIFY_CERTS``: set to ``false`` to disable verification. Lab use
  only: credentials are then sent to whoever answers on ``ES_HOST``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("linux_anomaly_detection")

VERIFY_CERTS_ENV = "ES_VERIFY_CERTS"
CA_CERT_ENV = "ES_CA_CERT"
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})
_TLS_FAILURE_MARKERS = ("certificate_verify_failed", "certificate verify failed")

_insecure_warning_logged = False


def _parse_bool(value: bool | str) -> bool:
    """Interpret a config or environment value as a boolean (default true)."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in _FALSE_VALUES


def es_tls_kwargs(
    verify_certs: bool | str | None = None,
    ca_certs: str | None = None,
) -> dict[str, Any]:
    """Return TLS keyword arguments for ``elasticsearch.Elasticsearch``.

    Explicit arguments win; otherwise ``ES_VERIFY_CERTS`` (default true) and
    ``ES_CA_CERT`` are read from the environment.

    Args:
        verify_certs: Whether to verify the server certificate.
        ca_certs: Path to a CA bundle used for verification.

    Returns:
        Keyword arguments to pass to the client constructor.

    Raises:
        FileNotFoundError: ``ca_certs`` / ``ES_CA_CERT`` names a missing file.
    """
    global _insecure_warning_logged

    if verify_certs is None:
        verify_certs = os.getenv(VERIFY_CERTS_ENV, "true")
    if not _parse_bool(verify_certs):
        if not _insecure_warning_logged:
            logger.warning(
                f"Elasticsearch TLS certificate verification is disabled ({VERIFY_CERTS_ENV}=false); "
                f"credentials can be intercepted. Set {CA_CERT_ENV} instead."
            )
            _insecure_warning_logged = True
        return {"verify_certs": False, "ssl_show_warn": False}

    kwargs: dict[str, Any] = {"verify_certs": True}
    ca_path = ca_certs if ca_certs else os.getenv(CA_CERT_ENV, "")
    if ca_path:
        path = Path(ca_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"{CA_CERT_ENV} points to a missing file: {path}")
        kwargs["ca_certs"] = str(path)
    return kwargs


def tls_failure_hint(exc: BaseException) -> str | None:
    """Return a remediation hint when ``exc`` is a certificate verification failure."""
    text = f"{exc!r} {exc}".lower()
    if any(marker in text for marker in _TLS_FAILURE_MARKERS):
        return (
            f"TLS certificate verification failed. Set {CA_CERT_ENV}=/path/to/ca.pem "
            f"(the cluster's http_ca.crt), or {VERIFY_CERTS_ENV}=false for a lab cluster."
        )
    return None


def diagnose_connection_failure(es: Any) -> str | None:
    """Explain why ``es.ping()`` returned False, if the cause is TLS verification.

    ``ping()`` swallows the underlying error, so this repeats one request to
    surface it. Only call it after a failed ping.

    Args:
        es: An ``elasticsearch.Elasticsearch`` client.

    Returns:
        A hint for certificate failures, otherwise None.
    """
    try:
        es.info()
    except Exception as exc:  # noqa: BLE001 - any transport error is inspected, none re-raised
        return tls_failure_hint(exc)
    return None
