"""Verificações de segurança na máquina local — Windows e Linux."""

from __future__ import annotations

import platform
import socket
import subprocess
from dataclasses import dataclass


@dataclass
class FirewallProfile:
    name: str
    enabled: bool
    fix_command: str


@dataclass
class DefenderStatus:
    av_enabled: bool
    real_time_protection: bool
    av_name: str = "Antivírus"
    rtp_name: str = "Proteção em tempo real"


@dataclass
class RiskyPortInfo:
    port: int
    service: str
    reason: str
    severity: str
    fix_command: str


RISKY_PORTS: dict[int, RiskyPortInfo] = {
    21: RiskyPortInfo(21, "FTP", "Transmite credenciais em texto puro", "high",
        'netsh advfirewall firewall add rule name="Block FTP" dir=in action=block protocol=tcp localport=21'
        if platform.system() == "Windows" else
        'ufw deny 21/tcp'),
    23: RiskyPortInfo(23, "Telnet", "Transmite tudo sem criptografia", "critical",
        'netsh advfirewall firewall add rule name="Block Telnet" dir=in action=block protocol=tcp localport=23'
        if platform.system() == "Windows" else
        'ufw deny 23/tcp'),
    135: RiskyPortInfo(135, "RPC/DCOM", "Vetor comum de exploits remotos no Windows", "high",
        'netsh advfirewall firewall add rule name="Block RPC" dir=in action=block protocol=tcp localport=135 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 135/tcp'),
    139: RiskyPortInfo(139, "NetBIOS", "Expõe informações da rede — vetor de ransomware", "high",
        'netsh advfirewall firewall add rule name="Block NetBIOS" dir=in action=block protocol=tcp localport=139 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 139/tcp'),
    445: RiskyPortInfo(445, "SMB", "Principal vetor de ransomware (WannaCry, NotPetya)", "critical",
        'netsh advfirewall firewall add rule name="Block SMB Externo" dir=in action=block protocol=tcp localport=445 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 445/tcp'),
    3389: RiskyPortInfo(3389, "RDP", "RDP exposto é alvo constante de força bruta", "critical",
        'netsh advfirewall firewall add rule name="Block RDP Externo" dir=in action=block protocol=tcp localport=3389 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 3389/tcp'),
    5900: RiskyPortInfo(5900, "VNC", "VNC sem autenticação forte permite acesso remoto", "high",
        'netsh advfirewall firewall add rule name="Block VNC" dir=in action=block protocol=tcp localport=5900 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 5900/tcp'),
    6379: RiskyPortInfo(6379, "Redis", "Redis sem autenticação expõe todos os dados", "critical",
        'netsh advfirewall firewall add rule name="Block Redis" dir=in action=block protocol=tcp localport=6379 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 6379/tcp && # Edite /etc/redis/redis.conf: bind 127.0.0.1'),
    27017: RiskyPortInfo(27017, "MongoDB", "MongoDB sem autenticação expõe banco de dados", "critical",
        'netsh advfirewall firewall add rule name="Block MongoDB" dir=in action=block protocol=tcp localport=27017 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 27017/tcp'),
    5432: RiskyPortInfo(5432, "PostgreSQL", "Banco de dados exposto externamente", "high",
        'netsh advfirewall firewall add rule name="Block PostgreSQL" dir=in action=block protocol=tcp localport=5432 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 5432/tcp'),
    3306: RiskyPortInfo(3306, "MySQL/MariaDB", "Banco de dados exposto externamente", "high",
        'netsh advfirewall firewall add rule name="Block MySQL" dir=in action=block protocol=tcp localport=3306 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 3306/tcp'),
    1433: RiskyPortInfo(1433, "SQL Server", "Banco de dados exposto externamente", "high",
        'netsh advfirewall firewall add rule name="Block MSSQL" dir=in action=block protocol=tcp localport=1433 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 1433/tcp'),
    8080: RiskyPortInfo(8080, "HTTP Alternativo", "HTTP sem TLS — dados em texto puro", "medium",
        'netsh advfirewall firewall add rule name="Block HTTP Alt" dir=in action=block protocol=tcp localport=8080 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 8080/tcp'),
    9200: RiskyPortInfo(9200, "Elasticsearch", "Elasticsearch sem auth expõe todos os índices", "critical",
        'netsh advfirewall firewall add rule name="Block Elastic" dir=in action=block protocol=tcp localport=9200 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 9200/tcp'),
    11211: RiskyPortInfo(11211, "Memcached", "Vetor de amplificação DDoS e vazamento de dados", "critical",
        'netsh advfirewall firewall add rule name="Block Memcached" dir=in action=block protocol=tcp localport=11211 remoteip=!LocalSubnet'
        if platform.system() == "Windows" else
        'ufw deny 11211/tcp'),
}

EXTRA_PORTS = [1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 11211, 27017]


def get_hostname() -> str:
    return socket.gethostname()


def check_firewall() -> list[FirewallProfile]:
    if platform.system() == "Windows":
        return _firewall_windows()
    return _firewall_linux()


def _firewall_windows() -> list[FirewallProfile]:
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout
        profiles = []
        for name in ("Domain", "Private", "Public"):
            try:
                block = output.split(f"{name} Profile Settings")[1].split("Profile Settings")[0]
                enabled = "State                                 ON" in block
            except IndexError:
                enabled = False
            profiles.append(FirewallProfile(
                name=name,
                enabled=enabled,
                fix_command=f"netsh advfirewall set {name.lower()}profile state on",
            ))
        return profiles
    except Exception:
        return [
            FirewallProfile("Domain", False, "netsh advfirewall set domainprofile state on"),
            FirewallProfile("Private", False, "netsh advfirewall set privateprofile state on"),
            FirewallProfile("Public", False, "netsh advfirewall set publicprofile state on"),
        ]


def _firewall_linux() -> list[FirewallProfile]:
    # Tenta UFW primeiro
    try:
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
        enabled = "Status: active" in result.stdout
        return [FirewallProfile("UFW", enabled, "ufw enable")]
    except FileNotFoundError:
        pass

    # Fallback: verifica iptables
    try:
        result = subprocess.run(["iptables", "-L", "-n", "--line-numbers"],
                                capture_output=True, text=True, timeout=10)
        lines = [l for l in result.stdout.splitlines() if l and not l.startswith("Chain") and not l.startswith("target")]
        enabled = len(lines) > 0
        return [FirewallProfile(
            "iptables",
            enabled,
            "apt install ufw -y && ufw default deny incoming && ufw allow 22/tcp && ufw allow 8501/tcp && ufw enable",
        )]
    except Exception:
        return [FirewallProfile(
            "Firewall",
            False,
            "apt install ufw -y && ufw default deny incoming && ufw allow 22/tcp && ufw enable",
        )]


def check_defender() -> DefenderStatus:
    if platform.system() == "Windows":
        return _defender_windows()
    return _defender_linux()


def _defender_windows() -> DefenderStatus:
    def _ps(cmd: str) -> bool:
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=15,
            )
            return "True" in r.stdout
        except Exception:
            return False

    return DefenderStatus(
        av_enabled=_ps("(Get-MpComputerStatus).AntivirusEnabled"),
        real_time_protection=_ps("(Get-MpComputerStatus).RealTimeProtectionEnabled"),
        av_name="Windows Defender",
        rtp_name="Proteção em tempo real",
    )


def _defender_linux() -> DefenderStatus:
    def _active(service: str) -> bool:
        try:
            r = subprocess.run(["systemctl", "is-active", service],
                               capture_output=True, text=True, timeout=5)
            return r.stdout.strip() == "active"
        except Exception:
            return False

    def _installed(cmd: str) -> bool:
        try:
            r = subprocess.run(["which", cmd], capture_output=True, text=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    av = _installed("clamscan") or _active("clamav-freshclam")
    rtp = _active("fail2ban")

    return DefenderStatus(
        av_enabled=av,
        real_time_protection=rtp,
        av_name="ClamAV (antivírus)",
        rtp_name="fail2ban (proteção ativa)",
    )


def build_remediation(
    firewall_profiles: list[FirewallProfile],
    defender: DefenderStatus,
    risky_found: list[RiskyPortInfo],
) -> list[tuple[str, str]]:
    commands: list[tuple[str, str]] = []
    is_linux = platform.system() != "Windows"

    for p in firewall_profiles:
        if not p.enabled:
            commands.append((f"Ativar firewall — {p.name}", p.fix_command))

    if not defender.av_enabled:
        if is_linux:
            commands.append(("Instalar ClamAV (antivírus)",
                             "apt install clamav clamav-daemon -y && freshclam && systemctl enable clamav-daemon && systemctl start clamav-daemon"))
        else:
            commands.append(("Ativar Windows Defender",
                             "Set-MpPreference -DisableRealtimeMonitoring $false"))

    if not defender.real_time_protection:
        if is_linux:
            commands.append(("Instalar fail2ban (proteção contra força bruta)",
                             "apt install fail2ban -y && systemctl enable fail2ban && systemctl start fail2ban"))
        else:
            commands.append(("Ativar proteção em tempo real",
                             "Set-MpPreference -DisableRealtimeMonitoring $false"))

    for rp in risky_found:
        commands.append((
            f"Bloquear porta {rp.port} ({rp.service}) — {rp.reason}",
            rp.fix_command,
        ))

    if not commands:
        commands.append(("Nenhuma remediação necessária", "# Tudo OK!"))

    return commands
