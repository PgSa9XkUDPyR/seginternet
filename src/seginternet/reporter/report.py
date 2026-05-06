"""Geração de relatório consolidado em JSON."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any


def _to_serializable(obj: Any) -> Any:
    """Converte dataclasses (inclusive aninhados) e outros tipos para tipos JSON."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_serializable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_serializable(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    return obj


def _count_severities(results: dict[str, Any]) -> dict[str, int]:
    """Percorre recursivamente os resultados e conta ocorrências por severidade."""
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def _walk(obj: Any) -> None:
        if isinstance(obj, dict):
            if "severity" in obj and isinstance(obj["severity"], str):
                sev = obj["severity"].lower()
                if sev in counts:
                    counts[sev] += 1
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(_to_serializable(results))
    return counts


def generate_report(host: str, results: dict[str, Any]) -> str:
    """Serializa todos os resultados em um relatório JSON.

    Args:
        host: Host/domínio analisado.
        results: Dicionário com chaves descritivas (ex.: "ports", "ssl")
                 mapeando para dataclasses ou listas de dataclasses.

    Returns:
        String JSON formatada (indent=2).
    """
    serializable_results = _to_serializable(results)
    severity_summary = _count_severities(results)

    report = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "host": host,
        "severity_summary": severity_summary,
        "results": serializable_results,
    }

    return json.dumps(report, ensure_ascii=False, indent=2)
