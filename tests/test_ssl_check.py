"""Testes para seginternet.scanner.ssl_check."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, call

import pytest

from seginternet.scanner.ssl_check import check_ssl, SSLResult


def _build_cert(days_offset: int, self_signed: bool = False) -> dict:
    """Gera um dicionário de certificado simulado."""
    expiry = datetime.now(tz=timezone.utc) + timedelta(days=days_offset)
    # ssl retorna a data nesse formato: "May  5 12:00:00 2026 GMT"
    not_after = expiry.strftime("%b %d %H:%M:%S %Y GMT")

    issuer = ((("commonName", "Test CA"),),) if not self_signed else ((("commonName", "example.com"),),)
    subject = ((("commonName", "example.com"),),)

    return {
        "notAfter": not_after,
        "issuer": issuer,
        "subject": subject,
    }


def _setup_ssl_mocks(cert: dict, protocol: str = "TLSv1.3"):
    """Retorna mocks configurados para create_connection e SSLContext."""
    raw_sock = MagicMock()
    tls_sock = MagicMock()
    tls_sock.version.return_value = protocol
    tls_sock.getpeercert.return_value = cert
    tls_sock.__enter__ = MagicMock(return_value=tls_sock)
    tls_sock.__exit__ = MagicMock(return_value=False)

    raw_sock.__enter__ = MagicMock(return_value=raw_sock)
    raw_sock.__exit__ = MagicMock(return_value=False)

    ctx = MagicMock()
    ctx.wrap_socket.return_value = tls_sock

    return raw_sock, tls_sock, ctx


class TestCheckSSL:
    def test_valid_certificate(self) -> None:
        """Certificado válido com 90 dias restantes deve ser detectado corretamente."""
        cert = _build_cert(days_offset=90)
        raw_sock, tls_sock, ctx = _setup_ssl_mocks(cert, protocol="TLSv1.3")

        with patch("seginternet.scanner.ssl_check.ssl.create_default_context", return_value=ctx), \
             patch("seginternet.scanner.ssl_check.socket.create_connection", return_value=raw_sock), \
             patch("seginternet.scanner.ssl_check._detect_weak_protocols", return_value=[]):

            result = check_ssl("example.com", port=443)

        assert result.host == "example.com"
        assert result.port == 443
        assert result.protocol_version == "TLSv1.3"
        assert result.days_until_expiry >= 89  # margem de 1 dia para execução do teste
        assert result.is_self_signed is False
        assert result.weak_protocols == []

    def test_expired_certificate(self) -> None:
        """Certificado expirado deve ter days_until_expiry negativo."""
        cert = _build_cert(days_offset=-10)
        raw_sock, tls_sock, ctx = _setup_ssl_mocks(cert)

        with patch("seginternet.scanner.ssl_check.ssl.create_default_context", return_value=ctx), \
             patch("seginternet.scanner.ssl_check.socket.create_connection", return_value=raw_sock), \
             patch("seginternet.scanner.ssl_check._detect_weak_protocols", return_value=[]):

            result = check_ssl("expired.example.com")

        assert result.days_until_expiry < 0

    def test_self_signed_certificate(self) -> None:
        """Certificado auto-assinado deve ter is_self_signed=True."""
        cert = _build_cert(days_offset=365, self_signed=True)
        raw_sock, tls_sock, ctx = _setup_ssl_mocks(cert)

        with patch("seginternet.scanner.ssl_check.ssl.create_default_context", return_value=ctx), \
             patch("seginternet.scanner.ssl_check.socket.create_connection", return_value=raw_sock), \
             patch("seginternet.scanner.ssl_check._detect_weak_protocols", return_value=[]):

            result = check_ssl("self-signed.example.com")

        assert result.is_self_signed is True

    def test_weak_protocols_detected(self) -> None:
        """Protocolos fracos detectados devem aparecer na lista."""
        cert = _build_cert(days_offset=180)
        raw_sock, tls_sock, ctx = _setup_ssl_mocks(cert)

        with patch("seginternet.scanner.ssl_check.ssl.create_default_context", return_value=ctx), \
             patch("seginternet.scanner.ssl_check.socket.create_connection", return_value=raw_sock), \
             patch(
                 "seginternet.scanner.ssl_check._detect_weak_protocols",
                 return_value=["TLS 1.0", "TLS 1.1"],
             ):

            result = check_ssl("weak.example.com")

        assert "TLS 1.0" in result.weak_protocols
        assert "TLS 1.1" in result.weak_protocols

    def test_connection_error_raises_descriptive_exception(self) -> None:
        """Falha de conexão SSL deve levantar ConnectionError com mensagem em português."""
        with patch(
            "seginternet.scanner.ssl_check.socket.create_connection",
            side_effect=OSError("connection refused"),
        ):
            with pytest.raises(ConnectionError, match="conexão SSL"):
                check_ssl("unreachable.example.com")

    def test_issuer_and_subject_parsed(self) -> None:
        """Issuer e subject devem ser strings legíveis."""
        cert = _build_cert(days_offset=30)
        raw_sock, tls_sock, ctx = _setup_ssl_mocks(cert)

        with patch("seginternet.scanner.ssl_check.ssl.create_default_context", return_value=ctx), \
             patch("seginternet.scanner.ssl_check.socket.create_connection", return_value=raw_sock), \
             patch("seginternet.scanner.ssl_check._detect_weak_protocols", return_value=[]):

            result = check_ssl("example.com")

        assert "commonName" in result.issuer
        assert "commonName" in result.subject
