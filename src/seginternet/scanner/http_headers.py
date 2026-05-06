"""Análise de cabeçalhos HTTP de segurança."""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class HeaderResult:
    header: str
    present: bool
    value: str | None
    severity: str  # "high" | "medium" | "low"


# (header_name, severity_when_missing)
_SECURITY_HEADERS: list[tuple[str, str]] = [
    ("Strict-Transport-Security", "high"),
    ("Content-Security-Policy", "high"),
    ("X-Frame-Options", "medium"),
    ("X-Content-Type-Options", "medium"),
    ("Referrer-Policy", "low"),
    ("Permissions-Policy", "low"),
    ("X-XSS-Protection", "low"),
]


def check_headers(url: str) -> list[HeaderResult]:
    """Analisa os cabeçalhos HTTP de segurança de *url*.

    Levanta httpx.RequestError em caso de falha de rede.
    Levanta ValueError se a URL for inválida.
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError(
            f"URL inválida: '{url}'. A URL deve começar com http:// ou https://"
        )

    try:
        response = httpx.get(url, follow_redirects=True, timeout=10.0)
    except httpx.RequestError as exc:
        raise httpx.RequestError(
            f"Falha ao conectar em '{url}': {exc}"
        ) from exc

    results: list[HeaderResult] = []
    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    for header_name, missing_severity in _SECURITY_HEADERS:
        key = header_name.lower()
        if key in headers_lower:
            results.append(
                HeaderResult(
                    header=header_name,
                    present=True,
                    value=headers_lower[key],
                    severity="low",
                )
            )
        else:
            results.append(
                HeaderResult(
                    header=header_name,
                    present=False,
                    value=None,
                    severity=missing_severity,
                )
            )

    return results
