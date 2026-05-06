"""Verificação de configuração SSL/TLS de um host."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class SSLResult:
    host: str
    port: int
    protocol_version: str
    cert_expiry: str          # ISO-8601
    issuer: str
    subject: str
    is_self_signed: bool
    weak_protocols: list[str]
    days_until_expiry: int


def _parse_rdns(rdns: tuple) -> str:  # type: ignore[type-arg]
    """Converte a estrutura de RDN retornada pelo ssl em string legível."""
    parts = []
    for rdn in rdns:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _cert_expiry(cert: dict) -> tuple[str, int]:  # type: ignore[type-arg]
    """Retorna (iso_string, days_until_expiry) a partir do dicionário do certificado."""
    not_after_str: str = cert["notAfter"]
    # Formato: "May  5 12:00:00 2026 GMT"
    expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    now = datetime.now(tz=timezone.utc)
    days = (expiry_dt - now).days
    return expiry_dt.isoformat(), days


def _detect_weak_protocols(host: str, port: int) -> list[str]:
    """Tenta conexões com protocolos considerados fracos para detectar suporte."""
    weak: list[str] = []

    candidates: list[tuple[str, int]] = []

    # TLS 1.0
    if hasattr(ssl, "TLSVersion"):
        candidates.append(("TLS 1.0", ssl.TLSVersion.TLSv1))
        candidates.append(("TLS 1.1", ssl.TLSVersion.TLSv1_1))

    for proto_name, tls_version in candidates:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((host, port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=host):
                    weak.append(proto_name)
        except (ssl.SSLError, OSError, ConnectionResetError):
            pass

    return weak


def check_ssl(host: str, port: int = 443) -> SSLResult:
    """Verifica a configuração SSL/TLS de *host*:*port*.

    Levanta ConnectionError se não for possível estabelecer conexão SSL.
    """
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                protocol_version: str = tls_sock.version() or "unknown"
                cert: dict = tls_sock.getpeercert()  # type: ignore[assignment]
    except (ssl.SSLError, OSError) as exc:
        raise ConnectionError(
            f"Não foi possível estabelecer conexão SSL com '{host}:{port}': {exc}"
        ) from exc

    issuer = _parse_rdns(cert.get("issuer", ()))
    subject = _parse_rdns(cert.get("subject", ()))
    is_self_signed = issuer == subject

    cert_expiry_iso, days_until_expiry = _cert_expiry(cert)
    weak_protocols = _detect_weak_protocols(host, port)

    return SSLResult(
        host=host,
        port=port,
        protocol_version=protocol_version,
        cert_expiry=cert_expiry_iso,
        issuer=issuer,
        subject=subject,
        is_self_signed=is_self_signed,
        weak_protocols=weak_protocols,
        days_until_expiry=days_until_expiry,
    )
