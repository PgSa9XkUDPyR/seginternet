"""Monitoramento de conexões de rede — detecta conexões suspeitas a RATs e backdoors."""

from __future__ import annotations

from dataclasses import dataclass, field

from .ioc_database import SUSPICIOUS_RAT_PORTS, TOR_PORTS


@dataclass
class NetworkFinding:
    local_addr: str
    remote_addr: str
    status: str
    pid: int
    process_name: str
    severity: str
    reason: str


@dataclass
class NetworkScanResult:
    findings: list[NetworkFinding] = field(default_factory=list)
    total_connections: int = 0
    error: str = ""


def analyze_connections() -> NetworkScanResult:
    try:
        import psutil
    except ImportError:
        return NetworkScanResult(error="psutil não instalado — execute: pip install psutil")

    result = NetworkScanResult()
    findings: list[NetworkFinding] = []

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, Exception) as exc:
        return NetworkScanResult(error=f"Acesso negado às conexões de rede: {exc}")

    pid_name_cache: dict[int, str] = {}

    def _proc_name(pid: int) -> str:
        if pid in pid_name_cache:
            return pid_name_cache[pid]
        try:
            name = psutil.Process(pid).name()
        except Exception:
            name = "desconhecido"
        pid_name_cache[pid] = name
        return name

    for conn in connections:
        if conn.status not in ("ESTABLISHED", "LISTEN", "SYN_SENT", "SYN_RECV"):
            continue

        result.total_connections += 1
        pid = conn.pid or 0
        proc_name = _proc_name(pid) if pid else "sistema"

        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?"
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""

        remote_port = conn.raddr.port if conn.raddr else None
        local_port = conn.laddr.port if conn.laddr else None

        # Conexão a porta de RAT conhecido
        if remote_port and remote_port in SUSPICIOUS_RAT_PORTS:
            findings.append(NetworkFinding(
                local_addr=local, remote_addr=remote, status=conn.status,
                pid=pid, process_name=proc_name,
                severity="critical",
                reason=f"Conexão à porta de RAT/backdoor: {SUSPICIOUS_RAT_PORTS[remote_port]}",
            ))
            continue

        # Serviço escutando em porta de RAT
        if not conn.raddr and local_port and local_port in SUSPICIOUS_RAT_PORTS:
            findings.append(NetworkFinding(
                local_addr=local, remote_addr="(ouvindo)", status=conn.status,
                pid=pid, process_name=proc_name,
                severity="high",
                reason=f"Processo escutando na porta de RAT: {SUSPICIOUS_RAT_PORTS[local_port]}",
            ))
            continue

        # Conexão a porta Tor
        if remote_port and remote_port in TOR_PORTS:
            findings.append(NetworkFinding(
                local_addr=local, remote_addr=remote, status=conn.status,
                pid=pid, process_name=proc_name,
                severity="medium",
                reason="Conexão à porta de rede Tor — verifique se é intencional",
            ))
            continue

        # Processo desconhecido com conexão de saída ativa (heurística leve)
        if conn.raddr and conn.status == "ESTABLISHED" and proc_name in ("desconhecido", ""):
            findings.append(NetworkFinding(
                local_addr=local, remote_addr=remote, status=conn.status,
                pid=pid, process_name=proc_name,
                severity="medium",
                reason="Conexão ativa por processo sem nome identificável",
            ))

    result.findings = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 4),
    )
    return result
