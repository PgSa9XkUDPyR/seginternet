"""Checklist de OpSec baseada em vetores reais de risco."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CheckItem:
    category: str
    risk: str
    description: str
    mitigation: str
    severity: str  # "critical" | "high" | "medium" | "low"


_CHECKLIST: list[CheckItem] = [
    CheckItem(
        category="Endpoint",
        risk="Malware no dispositivo",
        description="Malware captura dados antes da criptografia",
        mitigation="Use antivírus, mantenha SO atualizado, evite software pirata",
        severity="high",
    ),
    CheckItem(
        category="Navegador",
        risk="Fingerprint único do navegador",
        description=(
            "Canvas, WebGL, fontes e plugins criam identidade única "
            "independente do IP"
        ),
        mitigation="Use Tor Browser ou Firefox com arkenfox user.js",
        severity="high",
    ),
    CheckItem(
        category="Navegador",
        risk="Cookies persistentes",
        description=(
            "Cookies rastreiam sessões mesmo após troca de IP/VPN"
        ),
        mitigation=(
            "Use modo privado, limpe cookies, use containeres no Firefox"
        ),
        severity="high",
    ),
    CheckItem(
        category="Navegador",
        risk="WebRTC leak",
        description="WebRTC expõe IP real mesmo com VPN ativa",
        mitigation="Desative WebRTC no navegador ou use extensão",
        severity="high",
    ),
    CheckItem(
        category="DNS",
        risk="DNS leak via VPN",
        description="Consultas DNS podem escapar do túnel VPN",
        mitigation="Configure DNS-over-HTTPS, verifique com dnsleaktest.com",
        severity="high",
    ),
    CheckItem(
        category="Identidade",
        risk="Contas logadas durante atividade sensível",
        description=(
            "Login no Google/Facebook vincula identidade real ao "
            "comportamento, anulando VPN"
        ),
        mitigation="Use perfis separados, nunca misture contas pessoais",
        severity="critical",
    ),
    CheckItem(
        category="Identidade",
        risk="Correlação de contas",
        description=(
            "Usar mesma conta em contextos diferentes permite correlação"
        ),
        mitigation="Compartimentalize identidades completamente",
        severity="critical",
    ),
    CheckItem(
        category="Operacional",
        risk="Reutilização de senhas",
        description=(
            "Senhas reutilizadas permitem acesso cruzado após vazamento"
        ),
        mitigation="Use gerenciador de senhas (Bitwarden, KeePass)",
        severity="high",
    ),
    CheckItem(
        category="Operacional",
        risk="2FA por SMS",
        description="SIM swap compromete 2FA por SMS",
        mitigation=(
            "Use TOTP (Authy, Google Authenticator) ou chave física (YubiKey)"
        ),
        severity="medium",
    ),
    CheckItem(
        category="Rede",
        risk="Wi-Fi público sem VPN",
        description="Redes abertas permitem MITM e sniffing",
        mitigation="Sempre use VPN em redes públicas, prefira 4G/5G",
        severity="high",
    ),
]


def get_checklist() -> list[CheckItem]:
    """Retorna a checklist de OpSec com vetores reais de risco."""
    return list(_CHECKLIST)
