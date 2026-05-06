"""Consulta informações sobre o IP público atual."""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class IPInfo:
    ip: str
    country: str
    region: str
    city: str
    isp: str
    timezone: str
    org: str


def get_ip_info(ip: str | None = None) -> IPInfo:
    """Obtém informações do IP público via ipapi.co.

    Se *ip* for fornecido, consulta aquele IP específico; caso contrário usa o IP de saída do servidor.
    Levanta ConnectionError se a requisição falhar.
    Levanta RuntimeError se a API retornar erro (ex.: rate limit).
    """
    url = f"https://ipapi.co/{ip}/json/" if ip else "https://ipapi.co/json/"
    try:
        response = httpx.get(url, timeout=10.0)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"A API ipapi.co retornou erro {exc.response.status_code}. "
            "Verifique se você não atingiu o limite de requisições gratuitas."
        ) from exc
    except httpx.RequestError as exc:
        raise ConnectionError(
            f"Falha ao consultar informações de IP: {exc}"
        ) from exc

    data = response.json()

    if "error" in data:
        raise RuntimeError(
            f"Erro retornado pela API ipapi.co: {data.get('reason', data['error'])}"
        )

    return IPInfo(
        ip=data.get("ip", "N/A"),
        country=data.get("country_name", "N/A"),
        region=data.get("region", "N/A"),
        city=data.get("city", "N/A"),
        isp=data.get("isp", "N/A"),
        timezone=data.get("timezone", "N/A"),
        org=data.get("org", "N/A"),
    )
