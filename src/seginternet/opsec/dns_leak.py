"""Detecção de vazamento de DNS (DNS leak)."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

import httpx


@dataclass
class DNSLeakResult:
    domain: str
    doh_ips: list[str]
    local_ips: list[str]
    potential_leak: bool


def _resolve_via_doh(domain: str) -> list[str]:
    """Resolve *domain* usando DNS-over-HTTPS da Cloudflare."""
    url = f"https://1.1.1.1/dns-query?name={domain}&type=A"
    headers = {"Accept": "application/dns-json"}
    try:
        response = httpx.get(url, headers=headers, timeout=10.0)
        response.raise_for_status()
        data = response.json()
        return [
            answer["data"]
            for answer in data.get("Answer", [])
            if answer.get("type") == 1  # tipo A
        ]
    except httpx.HTTPError as exc:
        raise ConnectionError(
            f"Falha ao consultar DNS-over-HTTPS para '{domain}': {exc}"
        ) from exc


def _resolve_local(domain: str) -> list[str]:
    """Resolve *domain* usando o DNS local do sistema."""
    try:
        info = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({entry[4][0] for entry in info})
    except socket.gaierror as exc:
        raise ConnectionError(
            f"Falha na resolução DNS local para '{domain}': {exc}"
        ) from exc


def check_dns_leak(domain: str = "example.com") -> DNSLeakResult:
    """Compara resolução DoH (Cloudflare) com DNS local para detectar possível leak.

    Um resultado potential_leak=True indica que os conjuntos de IPs diferem,
    o que pode (mas não necessariamente) indicar vazamento de DNS.
    """
    doh_ips = sorted(set(_resolve_via_doh(domain)))
    local_ips = sorted(set(_resolve_local(domain)))

    potential_leak = set(doh_ips) != set(local_ips)

    return DNSLeakResult(
        domain=domain,
        doh_ips=doh_ips,
        local_ips=local_ips,
        potential_leak=potential_leak,
    )
