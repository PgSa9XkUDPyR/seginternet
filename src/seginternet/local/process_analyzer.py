"""Análise de processos em execução — detecta processos maliciosos ou suspeitos."""

from __future__ import annotations

import platform
from dataclasses import dataclass, field

from .ioc_database import (
    KNOWN_MALICIOUS_PROCESS_NAMES,
    SUSPICIOUS_PATH_SUBSTRINGS,
    SYSTEM_PROCESS_EXPECTED_PATHS,
)


@dataclass
class ProcessFinding:
    pid: int
    name: str
    path: str
    user: str
    severity: str   # critical | high | medium | low
    reason: str
    category: str   # known_malware | system_impersonation | suspicious_path


@dataclass
class ProcessScanResult:
    findings: list[ProcessFinding] = field(default_factory=list)
    total_processes: int = 0
    error: str = ""


def analyze_processes() -> ProcessScanResult:
    try:
        import psutil
    except ImportError:
        return ProcessScanResult(error="psutil não instalado — execute: pip install psutil")

    result = ProcessScanResult()
    findings: list[ProcessFinding] = []

    try:
        procs = list(psutil.process_iter(["pid", "name", "exe", "username"]))
    except Exception as exc:
        return ProcessScanResult(error=f"Erro ao listar processos: {exc}")

    result.total_processes = len(procs)

    for proc in procs:
        try:
            info = proc.info
            name: str = (info.get("name") or "").strip()
            exe: str = (info.get("exe") or "").strip()
            user: str = (info.get("username") or "desconhecido").strip()
            pid: int = info.get("pid", 0)
            name_lower = name.lower()
            exe_lower = exe.lower()

            # 1 — Nome corresponde a malware conhecido
            if name_lower in KNOWN_MALICIOUS_PROCESS_NAMES:
                findings.append(ProcessFinding(
                    pid=pid, name=name, path=exe, user=user,
                    severity="critical",
                    reason=f"Nome de malware/RAT conhecido na base de IoCs",
                    category="known_malware",
                ))
                continue

            # 2 — Processo de sistema executando fora do local esperado (Windows)
            if platform.system() == "Windows" and name_lower in SYSTEM_PROCESS_EXPECTED_PATHS:
                expected = SYSTEM_PROCESS_EXPECTED_PATHS[name_lower]
                if exe and expected not in exe_lower:
                    findings.append(ProcessFinding(
                        pid=pid, name=name, path=exe, user=user,
                        severity="critical",
                        reason=f"Processo de sistema fora do caminho esperado ({expected})",
                        category="system_impersonation",
                    ))
                    continue

            # 3 — Executável em diretório temporário/suspeito
            if exe and any(s in exe_lower for s in SUSPICIOUS_PATH_SUBSTRINGS):
                findings.append(ProcessFinding(
                    pid=pid, name=name, path=exe, user=user,
                    severity="high",
                    reason="Executável rodando de diretório temporário ou suspeito",
                    category="suspicious_path",
                ))

        except (Exception,):
            continue

    result.findings = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 4),
    )
    return result
