"""Varredura de chaves de registro de persistência — Windows apenas."""

from __future__ import annotations

import platform
from dataclasses import dataclass, field

from .ioc_database import (
    HIVE_NAMES,
    REGISTRY_AUTORUN_KEYS,
    SUSPICIOUS_PATH_SUBSTRINGS,
    SUSPICIOUS_SCRIPT_EXTENSIONS,
)


@dataclass
class RegistryFinding:
    hive: str
    key: str
    value_name: str
    value_data: str
    severity: str
    reason: str


@dataclass
class RegistryScanResult:
    findings: list[RegistryFinding] = field(default_factory=list)
    keys_scanned: int = 0
    error: str = ""
    skipped: bool = False


def scan_registry() -> RegistryScanResult:
    if platform.system() != "Windows":
        return RegistryScanResult(skipped=True, error="Análise de registro disponível apenas no Windows.")

    try:
        import winreg
    except ImportError:
        return RegistryScanResult(error="winreg não disponível neste ambiente.")

    result = RegistryScanResult()
    findings: list[RegistryFinding] = []

    for hive_const, key_path in REGISTRY_AUTORUN_KEYS:
        result.keys_scanned += 1
        hive_name = HIVE_NAMES.get(hive_const, str(hive_const))

        try:
            with winreg.OpenKey(hive_const, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        i += 1
                        data_str = str(val_data)
                        severity, reason = _classify_entry(val_name, data_str)
                        if severity:
                            findings.append(RegistryFinding(
                                hive=hive_name,
                                key=key_path,
                                value_name=val_name,
                                value_data=data_str[:300],
                                severity=severity,
                                reason=reason,
                            ))
                    except OSError:
                        break
        except (OSError, PermissionError):
            continue

    result.findings = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 4),
    )
    return result


def _classify_entry(name: str, data: str) -> tuple[str, str]:
    """Retorna (severity, reason) ou ("", "") se não suspeito."""
    data_lower = data.lower()
    name_lower = name.lower()

    # Entrada em caminho temporário/suspeito
    if any(s in data_lower for s in SUSPICIOUS_PATH_SUBSTRINGS):
        return "high", "Autorun aponta para diretório temporário ou suspeito"

    # Extensão de script suspeita na entrada
    ext = _get_extension(data_lower)
    if ext in SUSPICIOUS_SCRIPT_EXTENSIONS - {".exe", ".dll"}:
        return "high", f"Autorun executa script suspeito ({ext})"

    # Winlogon entries suspeitas
    if "userinit" in name_lower or "shell" in name_lower:
        # Valores padrão esperados
        if "userinit" in name_lower and "userinit.exe," not in data_lower:
            return "critical", "Winlogon Userinit modificado — possível hijack de login"
        if name_lower == "shell" and data_lower not in ("explorer.exe", ""):
            return "critical", "Winlogon Shell modificado — possível substituto malicioso"

    # AppInit_DLLs preenchido (deveria estar vazio)
    if name_lower == "appinit_dlls" and data.strip():
        return "high", "AppInit_DLLs configurado — DLL injetada em todos os processos"

    return "", ""


def _get_extension(path_lower: str) -> str:
    import os
    _, ext = os.path.splitext(path_lower.split('"')[0].split(" ")[0])
    return ext
