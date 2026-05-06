"""Testes para seginternet.scanner.dns_check."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import dns.resolver
import dns.exception

from seginternet.scanner.dns_check import check_dns, DNSResult


def _make_answer(strings: list[str]) -> list[MagicMock]:
    """Cria lista de mocks que simulam registros DNS retornados pelo dnspython."""
    return [MagicMock(__str__=MagicMock(return_value=s)) for s in strings]


class TestCheckDNS:
    def test_domain_with_spf_and_dmarc(self) -> None:
        """Domínio com SPF e DMARC deve ter has_spf=True e has_dmarc=True."""

        def mock_resolve(domain: str, record_type: str, **kwargs):
            if record_type == "TXT" and not domain.startswith("_dmarc"):
                return _make_answer(['"v=spf1 include:_spf.google.com ~all"'])
            if record_type == "TXT" and domain.startswith("_dmarc"):
                return _make_answer(['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'])
            if record_type == "MX":
                return _make_answer(["10 mail.example.com."])
            if record_type == "A":
                return _make_answer(["93.184.216.34"])
            if record_type == "AAAA":
                raise dns.resolver.NoAnswer()
            if record_type == "RRSIG":
                raise dns.resolver.NoAnswer()
            raise dns.resolver.NoAnswer()

        with patch("seginternet.scanner.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
            result = check_dns("example.com")

        assert result.has_spf is True
        assert result.spf_record is not None
        assert "v=spf1" in result.spf_record
        assert result.has_dmarc is True
        assert result.dmarc_record is not None
        assert "v=DMARC1" in result.dmarc_record

    def test_domain_without_security_records(self) -> None:
        """Domínio sem SPF, DMARC e DNSSEC deve ter os flags False."""

        def mock_resolve(domain: str, record_type: str, **kwargs):
            raise dns.resolver.NoAnswer()

        with patch("seginternet.scanner.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
            result = check_dns("nosec.example.com")

        assert result.has_spf is False
        assert result.spf_record is None
        assert result.has_dmarc is False
        assert result.dmarc_record is None
        assert result.has_dnssec is False
        assert result.mx_records == []
        assert result.a_records == []

    def test_mx_records_parsed(self) -> None:
        """Registros MX devem ser extraídos corretamente."""

        def mock_resolve(domain: str, record_type: str, **kwargs):
            if record_type == "MX":
                return _make_answer(["10 mail1.example.com.", "20 mail2.example.com."])
            raise dns.resolver.NoAnswer()

        with patch("seginternet.scanner.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
            result = check_dns("example.com")

        assert len(result.mx_records) == 2
        assert any("mail1" in mx for mx in result.mx_records)
        assert any("mail2" in mx for mx in result.mx_records)

    def test_dnssec_detected_when_rrsig_present(self) -> None:
        """DNSSEC deve ser True quando existir registro RRSIG."""

        def mock_resolve(domain: str, record_type: str, **kwargs):
            if record_type == "RRSIG":
                return _make_answer(["rrsig_data"])
            raise dns.resolver.NoAnswer()

        with patch("seginternet.scanner.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
            result = check_dns("secure.example.com")

        assert result.has_dnssec is True

    def test_empty_domain_raises_value_error(self) -> None:
        """Domínio vazio deve levantar ValueError."""
        with pytest.raises(ValueError, match="vazio"):
            check_dns("")

    def test_domain_normalized(self) -> None:
        """Domínio com letras maiúsculas e ponto final deve ser normalizado."""

        def mock_resolve(domain: str, record_type: str, **kwargs):
            raise dns.resolver.NoAnswer()

        with patch("seginternet.scanner.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
            result = check_dns("EXAMPLE.COM.")

        assert result.domain == "example.com"

    def test_txt_without_spf_does_not_set_spf(self) -> None:
        """Registro TXT sem v=spf1 não deve ativar has_spf."""

        def mock_resolve(domain: str, record_type: str, **kwargs):
            if record_type == "TXT" and not domain.startswith("_dmarc"):
                return _make_answer(['"google-site-verification=abc123"'])
            raise dns.resolver.NoAnswer()

        with patch("seginternet.scanner.dns_check.dns.resolver.resolve", side_effect=mock_resolve):
            result = check_dns("example.com")

        assert result.has_spf is False
