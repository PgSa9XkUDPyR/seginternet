"""Testes para seginternet.scanner.http_headers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from seginternet.scanner.http_headers import check_headers, HeaderResult


def _make_response(headers: dict[str, str], status_code: int = 200) -> MagicMock:
    """Cria um mock de httpx.Response."""
    response = MagicMock()
    response.status_code = status_code
    response.headers = {k.lower(): v for k, v in headers.items()}
    return response


class TestCheckHeaders:
    def test_present_headers_detected_correctly(self) -> None:
        """Headers presentes devem ter present=True e value preenchido."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block",
        }

        with patch("seginternet.scanner.http_headers.httpx.get", return_value=_make_response(headers)):
            results = check_headers("https://example.com")

        for r in results:
            assert r.present is True, f"{r.header} deveria estar presente"
            assert r.value is not None
            assert r.severity == "low"

    def test_missing_hsts_generates_high_severity(self) -> None:
        """Ausência de HSTS deve gerar severity='high'."""
        with patch("seginternet.scanner.http_headers.httpx.get", return_value=_make_response({})):
            results = check_headers("https://example.com")

        hsts = next(r for r in results if r.header == "Strict-Transport-Security")
        assert hsts.present is False
        assert hsts.severity == "high"
        assert hsts.value is None

    def test_missing_x_frame_options_generates_medium_severity(self) -> None:
        """Ausência de X-Frame-Options deve gerar severity='medium'."""
        with patch("seginternet.scanner.http_headers.httpx.get", return_value=_make_response({})):
            results = check_headers("https://example.com")

        xfo = next(r for r in results if r.header == "X-Frame-Options")
        assert xfo.present is False
        assert xfo.severity == "medium"

    def test_missing_csp_generates_high_severity(self) -> None:
        """Ausência de CSP deve gerar severity='high'."""
        with patch("seginternet.scanner.http_headers.httpx.get", return_value=_make_response({})):
            results = check_headers("https://example.com")

        csp = next(r for r in results if r.header == "Content-Security-Policy")
        assert csp.present is False
        assert csp.severity == "high"

    def test_partial_headers(self) -> None:
        """Quando apenas alguns headers estão presentes, deve refletir corretamente."""
        headers = {
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
        }

        with patch("seginternet.scanner.http_headers.httpx.get", return_value=_make_response(headers)):
            results = check_headers("https://example.com")

        present_headers = {r.header for r in results if r.present}
        missing_headers = {r.header for r in results if not r.present}

        assert "Strict-Transport-Security" in present_headers
        assert "X-Content-Type-Options" in present_headers
        assert "Content-Security-Policy" in missing_headers
        assert "X-Frame-Options" in missing_headers

    def test_invalid_url_raises_value_error(self) -> None:
        """URL sem esquema http/https deve levantar ValueError."""
        with pytest.raises(ValueError, match="inválida"):
            check_headers("ftp://example.com")

    def test_plain_http_url_is_accepted(self) -> None:
        """URLs http:// devem ser aceitas (sem HSTS, obviamente)."""
        with patch("seginternet.scanner.http_headers.httpx.get", return_value=_make_response({})):
            results = check_headers("http://example.com")

        assert isinstance(results, list)
        assert len(results) == 7

    def test_returns_all_seven_headers(self) -> None:
        """Deve sempre retornar 7 entradas (uma por header verificado)."""
        with patch("seginternet.scanner.http_headers.httpx.get", return_value=_make_response({})):
            results = check_headers("https://example.com")

        assert len(results) == 7
