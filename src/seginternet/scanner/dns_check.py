"""Análise de registros DNS relevantes para segurança."""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.resolver
import dns.exception


@dataclass
class DNSResult:
    domain: str
    has_spf: bool
    spf_record: str | None
    has_dmarc: bool
    dmarc_record: str | None
    has_dnssec: bool
    mx_records: list[str]
    a_records: list[str]


def _query(domain: str, record_type: str) -> list[str]:
    """Consulta DNS e retorna lista de strings. Retorna [] se não houver registros."""
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=10)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return []
    except dns.exception.DNSException:
        return []


def _find_spf(txt_records: list[str]) -> str | None:
    for record in txt_records:
        stripped = record.strip('"')
        if stripped.startswith("v=spf1"):
            return stripped
    return None


def _find_dmarc(txt_records: list[str]) -> str | None:
    for record in txt_records:
        stripped = record.strip('"')
        if stripped.startswith("v=DMARC1"):
            return stripped
    return None


def _check_dnssec(domain: str) -> bool:
    """Verifica se o domínio possui registros RRSIG (DNSSEC assinado)."""
    try:
        dns.resolver.resolve(domain, "RRSIG", lifetime=10)
        return True
    except Exception:
        return False


def check_dns(domain: str) -> DNSResult:
    """Analisa registros DNS de segurança para *domain*.

    Levanta ValueError se o domínio for vazio.
    """
    if not domain or not domain.strip():
        raise ValueError("O domínio não pode ser vazio.")

    domain = domain.strip().lower().rstrip(".")

    txt_records = _query(domain, "TXT")
    dmarc_txt = _query(f"_dmarc.{domain}", "TXT")

    spf_record = _find_spf(txt_records)
    dmarc_record = _find_dmarc(dmarc_txt)

    mx_raw = _query(domain, "MX")
    mx_records = [r.split()[-1].rstrip(".") for r in mx_raw]

    a_records = _query(domain, "A") + _query(domain, "AAAA")

    has_dnssec = _check_dnssec(domain)

    return DNSResult(
        domain=domain,
        has_spf=spf_record is not None,
        spf_record=spf_record,
        has_dmarc=dmarc_record is not None,
        dmarc_record=dmarc_record,
        has_dnssec=has_dnssec,
        mx_records=mx_records,
        a_records=a_records,
    )
