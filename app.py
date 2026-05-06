"""Interface web do seginternet — Streamlit."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent / "src"))

from seginternet.scanner.ports import scan_ports
from seginternet.scanner.http_headers import check_headers
from seginternet.scanner.ssl_check import check_ssl
from seginternet.scanner.dns_check import check_dns
from seginternet.opsec.dns_leak import check_dns_leak
from seginternet.opsec.ip_info import get_ip_info
from seginternet.opsec.checklist import get_checklist
from seginternet.reporter.report import generate_report
from seginternet.local.machine_check import (
    get_hostname, check_firewall, check_defender, build_remediation, RISKY_PORTS, EXTRA_PORTS,
)

# ---------------------------------------------------------------------------
# Configuração da página
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="seginternet",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Autenticação
# ---------------------------------------------------------------------------

_APP_USER = os.environ.get("APP_USER", "admin")
_APP_PASSWORD_HASH = os.environ.get("APP_PASSWORD_HASH", "")


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _login_gate() -> bool:
    if st.session_state.get("authenticated"):
        return True

    st.markdown("""
    <style>
        .login-wrap { max-width: 380px; margin: 80px auto 0; }
    </style>
    <div class="login-wrap"></div>
    """, unsafe_allow_html=True)

    col = st.columns([1, 2, 1])[1]
    with col:
        st.markdown("## 🔒 seginternet")
        st.caption("Análise de segurança de internet")
        st.divider()
        with st.form("login_form"):
            username = st.text_input("Usuário")
            password = st.text_input("Senha", type="password")
            submitted = st.form_submit_button("Entrar", use_container_width=True)

        if submitted:
            if not _APP_PASSWORD_HASH:
                st.error("Servidor não configurado: defina APP_USER e APP_PASSWORD_HASH.")
            elif username == _APP_USER and _hash(password) == _APP_PASSWORD_HASH:
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Usuário ou senha incorretos.")

    return False


if not _login_gate():
    st.stop()

st.markdown("""
<style>
    .sev-critical { color: #ff4444; font-weight: 700; }
    .sev-high     { color: #ff7744; font-weight: 700; }
    .sev-medium   { color: #ffbb00; font-weight: 700; }
    .sev-low      { color: #4488ff; font-weight: 700; }
    .sev-ok       { color: #00cc66; }
    .port-open    { color: #00cc66; font-weight: 700; }
    .port-closed  { color: #666666; }
    table.seg { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    table.seg th { background: #1e2130; padding: 8px 12px; text-align: left; border-bottom: 2px solid #333; }
    table.seg td { padding: 7px 12px; border-bottom: 1px solid #2a2a3a; vertical-align: top; }
    table.seg tr:hover td { background: #1a1a2a; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; font-weight: 700; }
    .badge-critical { background: #ff4444; color: #fff; }
    .badge-high     { background: #ff7744; color: #fff; }
    .badge-medium   { background: #ffbb00; color: #111; }
    .badge-low      { background: #4488ff; color: #fff; }
    .badge-ok       { background: #00cc66; color: #111; }
    .info-row { display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 16px; }
    .info-card { background: #1e2130; border-radius: 8px; padding: 14px 20px; min-width: 180px; }
    .info-card .label { font-size: 0.75rem; color: #888; text-transform: uppercase; letter-spacing: .05em; }
    .info-card .value { font-size: 1.1rem; font-weight: 600; margin-top: 4px; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_CLASSES = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
}

_BADGE_CLASSES = {
    "critical": "badge-critical",
    "high": "badge-high",
    "medium": "badge-medium",
    "low": "badge-low",
    "ok": "badge-ok",
}


def badge(text: str, kind: str = "ok") -> str:
    cls = _BADGE_CLASSES.get(kind.lower(), "badge-ok")
    return f'<span class="badge {cls}">{text.upper()}</span>'


def yn(value: bool, true_label: str = "Sim", false_label: str = "Não") -> str:
    if value:
        return f'<span class="sev-ok">✔ {true_label}</span>'
    return f'<span class="sev-high">✘ {false_label}</span>'


def info_card(label: str, value: str) -> str:
    return (
        f'<div class="info-card">'
        f'<div class="label">{label}</div>'
        f'<div class="value">{value}</div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Sidebar — navegação
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## 🔒 seginternet")
    st.caption("Análise de segurança de internet")
    st.divider()
    page = st.radio(
        "Navegação",
        [
            "🖥️ Verificação da Máquina",
            "📡 Scanner — Portas TCP",
            "🌐 Scanner — HTTP Headers",
            "🔐 Scanner — SSL/TLS",
            "📋 Scanner — DNS",
            "💧 OpSec — DNS Leak",
            "🌍 OpSec — Meu IP",
            "✅ OpSec — Checklist",
            "📊 Relatório Completo",
        ],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("Ferramenta passiva/não-intrusiva. Use apenas em hosts que você tem autorização para analisar.")

# ---------------------------------------------------------------------------
# Página: Verificação da Máquina Atual
# ---------------------------------------------------------------------------

if page == "🖥️ Verificação da Máquina":
    hostname = get_hostname()
    st.title("🖥️ Verificação de Segurança da Máquina")
    import platform as _platform
    if _platform.system() != "Windows":
        st.info(
            f"ℹ️ **Modo servidor:** esta análise inspeciona a máquina onde o app está hospedado "
            f"(`{hostname}`), não o seu computador local. "
            "Para analisar sua máquina, instale e rode o seginternet localmente."
        )
    else:
        st.markdown(
            f"Análise completa de **`{hostname}`** — verifica firewall, antivírus, "
            "portas abertas e gera comandos de remediação para cada problema encontrado."
        )

    if st.button("⚡ Iniciar Verificação Completa", use_container_width=True, type="primary"):
        progress = st.progress(0)
        status = st.empty()
        results = {}

        # --- Firewall ---
        status.markdown("**1/5** — Verificando Windows Firewall...")
        firewall_profiles = check_firewall()
        results["firewall"] = firewall_profiles
        progress.progress(20)

        # --- Defender ---
        status.markdown("**2/5** — Verificando Windows Defender...")
        defender = check_defender()
        results["defender"] = defender
        progress.progress(40)

        # --- Port scan localhost ---
        status.markdown("**3/5** — Escaneando portas locais (1–1024 + portas críticas)...")
        ports_to_scan = list(range(1, 1025)) + [p for p in EXTRA_PORTS if p > 1024]
        ports_to_scan = sorted(set(ports_to_scan))
        try:
            all_port_results = scan_ports("127.0.0.1", start=min(ports_to_scan), end=max(ports_to_scan), timeout=0.3)
            open_ports = [r.port for r in all_port_results if r.state == "open"]
        except Exception as e:
            st.warning(f"Scan de portas: {e}")
            open_ports = []
        results["open_ports"] = open_ports
        progress.progress(60)

        # --- IP público ---
        status.markdown("**4/5** — Consultando IP público...")
        try:
            ip_info = get_ip_info()
            results["ip_info"] = ip_info
        except Exception as e:
            st.warning(f"IP público: {e}")
            results["ip_info"] = None
        progress.progress(80)

        # --- DNS Leak ---
        status.markdown("**5/5** — Testando DNS leak...")
        try:
            dns_leak = check_dns_leak("cloudflare.com")
            results["dns_leak"] = dns_leak
        except Exception as e:
            st.warning(f"DNS leak: {e}")
            results["dns_leak"] = None
        progress.progress(100)
        status.empty()

        st.divider()

        # ----------------------------------------------------------------
        # Seção 1: Proteções do Sistema
        # ----------------------------------------------------------------
        st.markdown("## 🛡️ Proteções do Sistema")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Windows Firewall")
            fw_rows = []
            for p in firewall_profiles:
                estado = '<span class="sev-ok">✔ Ativo</span>' if p.enabled else '<span class="sev-critical">✘ INATIVO</span>'
                fw_rows.append(f"<tr><td><b>{p.name}</b></td><td>{estado}</td></tr>")
            st.markdown(
                '<table class="seg"><thead><tr><th>Perfil</th><th>Estado</th></tr></thead><tbody>'
                + "".join(fw_rows) + "</tbody></table>",
                unsafe_allow_html=True,
            )

        with col2:
            st.markdown("#### Windows Defender")
            def_rows = [
                ("Antivírus", defender.av_enabled),
                ("Proteção em tempo real", defender.real_time_protection),
            ]
            def_html = "".join(
                f"<tr><td><b>{label}</b></td><td>{yn(ok)}</td></tr>"
                for label, ok in def_rows
            )
            st.markdown(
                '<table class="seg"><thead><tr><th>Proteção</th><th>Estado</th></tr></thead><tbody>'
                + def_html + "</tbody></table>",
                unsafe_allow_html=True,
            )

        # ----------------------------------------------------------------
        # Seção 2: Portas Abertas
        # ----------------------------------------------------------------
        st.divider()
        st.markdown("## 🔓 Portas Abertas")

        risky_found: list = []
        safe_open: list[int] = []

        for port in open_ports:
            if port in RISKY_PORTS:
                risky_found.append(RISKY_PORTS[port])
            else:
                safe_open.append(port)

        col_r, col_s = st.columns(2)

        with col_r:
            st.markdown(f"#### ⚠️ Portas de Risco ({len(risky_found)})")
            if risky_found:
                rows = []
                for rp in risky_found:
                    sev = badge(rp.severity, rp.severity)
                    rows.append(
                        f"<tr><td><b>{rp.port}</b></td><td>{rp.service}</td>"
                        f"<td>{rp.reason}</td><td>{sev}</td></tr>"
                    )
                st.markdown(
                    '<table class="seg"><thead><tr>'
                    "<th>Porta</th><th>Serviço</th><th>Risco</th><th>Sev.</th>"
                    "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>",
                    unsafe_allow_html=True,
                )
            else:
                st.success("Nenhuma porta de risco conhecida encontrada.")

        with col_s:
            st.markdown(f"#### ✅ Outras Portas Abertas ({len(safe_open)})")
            if safe_open:
                chunks = [safe_open[i:i+10] for i in range(0, len(safe_open), 10)]
                for chunk in chunks:
                    st.markdown(" ".join(f"`{p}`" for p in chunk))
            else:
                st.info("Nenhuma outra porta aberta detectada.")

        # ----------------------------------------------------------------
        # Seção 3: IP Público e DNS
        # ----------------------------------------------------------------
        st.divider()
        st.markdown("## 🌍 Exposição de Rede")
        col_ip, col_dns = st.columns(2)

        with col_ip:
            st.markdown("#### IP Público")
            if results["ip_info"]:
                info = results["ip_info"]
                cards = (
                    f'<div class="info-row">'
                    + info_card("IP", info.ip)
                    + info_card("País", info.country)
                    + info_card("ISP", info.isp)
                    + "</div>"
                )
                st.markdown(cards, unsafe_allow_html=True)
                st.caption(f"Organização: `{info.org}` | Fuso: `{info.timezone}`")
            else:
                st.warning("Não foi possível obter o IP público.")

        with col_dns:
            st.markdown("#### DNS Leak")
            if results["dns_leak"]:
                leak = results["dns_leak"]
                if leak.potential_leak:
                    st.warning(
                        f"⚠️ **Possível DNS leak!**\n\n"
                        f"DoH (Cloudflare): `{', '.join(leak.doh_ips)}`\n\n"
                        f"DNS local: `{', '.join(leak.local_ips)}`"
                    )
                else:
                    st.success(f"✔ Sem leak detectado.\n\nIPs: `{', '.join(leak.local_ips)}`")
            else:
                st.warning("Não foi possível testar DNS leak.")

        # ----------------------------------------------------------------
        # Seção 4: Plano de Remediação
        # ----------------------------------------------------------------
        st.divider()
        st.markdown("## 🔧 Plano de Remediação")
        st.markdown(
            "Comandos prontos para corrigir cada problema encontrado. "
            "Execute como **Administrador** no PowerShell."
        )

        remediation = build_remediation(firewall_profiles, defender, risky_found)

        if len(remediation) == 1 and remediation[0][0].startswith("Nenhuma"):
            st.success("✅ Nenhuma remediação necessária — sua máquina está bem configurada!")
        else:
            for i, (desc, cmd) in enumerate(remediation):
                with st.expander(f"🔧 {desc}", expanded=i < 3):
                    st.code(cmd, language="powershell")
                    st.caption("Copie o comando acima e execute como Administrador no PowerShell.")

            # Botão para baixar todos os comandos como script
            all_cmds = "\n\n".join(
                f"# {desc}\n{cmd}" for desc, cmd in remediation
            )
            full_script = (
                "# Script de Remediação — seginternet\n"
                f"# Gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"# Host: {hostname}\n"
                "# Execute como Administrador no PowerShell\n\n"
                + all_cmds
            )
            st.download_button(
                label="⬇️ Baixar script de remediação (.ps1)",
                data=full_script,
                file_name=f"remediation_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1",
                mime="text/plain",
                use_container_width=True,
            )

        # ----------------------------------------------------------------
        # Seção 5: Score de Segurança
        # ----------------------------------------------------------------
        st.divider()
        st.markdown("## 📊 Score de Segurança")

        issues = 0
        fw_off = sum(1 for p in firewall_profiles if not p.enabled)
        issues += fw_off * 3
        if not defender.av_enabled:
            issues += 4
        if not defender.real_time_protection:
            issues += 3
        for rp in risky_found:
            issues += {"critical": 5, "high": 3, "medium": 1}.get(rp.severity, 1)
        if results["dns_leak"] and results["dns_leak"].potential_leak:
            issues += 2

        max_issues = 30
        score = max(0, 100 - int((issues / max_issues) * 100))
        score = min(score, 100)

        if score >= 80:
            score_color = "#00cc66"
            score_label = "Bom"
        elif score >= 50:
            score_color = "#ffbb00"
            score_label = "Atenção"
        else:
            score_color = "#ff4444"
            score_label = "Crítico"

        st.markdown(
            f'<div style="text-align:center;padding:24px;">'
            f'<div style="font-size:4rem;font-weight:700;color:{score_color}">{score}/100</div>'
            f'<div style="font-size:1.2rem;color:{score_color}">{score_label}</div>'
            f'<div style="color:#888;margin-top:8px">Baseado em {len(remediation)} problema(s) encontrado(s)</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# Página: Scanner — Portas TCP
# ---------------------------------------------------------------------------

elif page == "📡 Scanner — Portas TCP":
    st.title("📡 Scanner de Portas TCP")
    st.markdown("Detecta portas abertas e serviços expostos em um host.")

    with st.form("form_ports"):
        col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
        host = col1.text_input("Host / IP", placeholder="exemplo.com ou 192.168.1.1")
        start_port = col2.number_input("Porta inicial", min_value=1, max_value=65535, value=1)
        end_port = col3.number_input("Porta final", min_value=1, max_value=65535, value=1024)
        timeout = col4.number_input("Timeout (s)", min_value=0.1, max_value=10.0, value=1.0, step=0.1)

        col_a, col_b = st.columns([1, 3])
        only_open = col_a.checkbox("Mostrar apenas abertas", value=True)
        submitted = st.form_submit_button("🔍 Escanear", use_container_width=False)

    if submitted:
        if not host.strip():
            st.error("Informe um host.")
        else:
            import ipaddress as _ipaddress
            try:
                resolved = socket.gethostbyname(host.strip())
                addr = _ipaddress.ip_address(resolved)
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                    st.error("Scan de IPs privados/internos não é permitido no modo hospedado.")
                    st.stop()
            except socket.gaierror:
                st.error(f"Não foi possível resolver o host: `{host.strip()}`")
                st.stop()

            with st.spinner(f"Escaneando portas {int(start_port)}–{int(end_port)} em **{host}**..."):
                try:
                    results = scan_ports(host, start=int(start_port), end=int(end_port), timeout=timeout)
                except (ValueError, ConnectionError) as e:
                    st.error(str(e))
                    st.stop()

            open_ports = [r for r in results if r.state == "open"]
            closed_count = len(results) - len(open_ports)

            col1, col2, col3 = st.columns(3)
            col1.metric("Portas verificadas", len(results))
            col2.metric("Abertas", len(open_ports), delta=None)
            col3.metric("Fechadas", closed_count)

            display = open_ports if only_open else results
            if not display:
                st.success("Nenhuma porta aberta encontrada no intervalo.")
            else:
                rows = []
                for r in display:
                    state_html = (
                        '<span class="port-open">● aberta</span>'
                        if r.state == "open"
                        else '<span class="port-closed">○ fechada</span>'
                    )
                    rows.append(f"<tr><td>{r.port}</td><td>{r.service}</td><td>{state_html}</td></tr>")

                table_html = (
                    '<table class="seg">'
                    "<thead><tr><th>Porta</th><th>Serviço</th><th>Estado</th></tr></thead>"
                    "<tbody>" + "".join(rows) + "</tbody></table>"
                )
                st.markdown(table_html, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Página: Scanner — HTTP Headers
# ---------------------------------------------------------------------------

elif page == "🌐 Scanner — HTTP Headers":
    st.title("🌐 Cabeçalhos HTTP de Segurança")
    st.markdown("Verifica presença e valores dos headers de segurança HTTP.")

    with st.form("form_http"):
        url = st.text_input("URL", placeholder="https://exemplo.com")
        submitted = st.form_submit_button("🔍 Verificar")

    if submitted:
        if not url.strip():
            st.error("Informe uma URL.")
        else:
            with st.spinner(f"Verificando headers de **{url}**..."):
                try:
                    results = check_headers(url)
                except Exception as e:
                    st.error(str(e))
                    st.stop()

            missing_high = [r for r in results if not r.present and r.severity == "high"]
            missing_medium = [r for r in results if not r.present and r.severity == "medium"]
            present = [r for r in results if r.present]

            col1, col2, col3 = st.columns(3)
            col1.metric("Headers presentes", len(present))
            col2.metric("Ausentes (high)", len(missing_high), delta=-len(missing_high) if missing_high else None, delta_color="inverse")
            col3.metric("Ausentes (medium)", len(missing_medium))

            rows = []
            for r in results:
                present_str = '<span class="sev-ok">✔ Presente</span>' if r.present else '<span class="sev-high">✘ Ausente</span>'
                value_str = f"<code>{r.value[:80]}</code>" if r.value else "<span style='color:#555'>—</span>"
                sev_str = badge("OK", "ok") if r.present else badge(r.severity, r.severity)
                rows.append(f"<tr><td><code>{r.header}</code></td><td>{present_str}</td><td>{value_str}</td><td>{sev_str}</td></tr>")

            table_html = (
                '<table class="seg">'
                "<thead><tr><th>Cabeçalho</th><th>Presente</th><th>Valor</th><th>Severidade</th></tr></thead>"
                "<tbody>" + "".join(rows) + "</tbody></table>"
            )
            st.markdown(table_html, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Página: Scanner — SSL/TLS
# ---------------------------------------------------------------------------

elif page == "🔐 Scanner — SSL/TLS":
    st.title("🔐 Verificação SSL/TLS")
    st.markdown("Analisa certificado, validade e protocolos suportados.")

    with st.form("form_ssl"):
        col1, col2 = st.columns([3, 1])
        host = col1.text_input("Host", placeholder="exemplo.com")
        port = col2.number_input("Porta", min_value=1, max_value=65535, value=443)
        submitted = st.form_submit_button("🔍 Verificar")

    if submitted:
        if not host.strip():
            st.error("Informe um host.")
        else:
            with st.spinner(f"Verificando SSL/TLS de **{host}:{int(port)}**..."):
                try:
                    result = check_ssl(host, port=int(port))
                except ConnectionError as e:
                    st.error(str(e))
                    st.stop()

            # Cores para dias até expirar
            if result.days_until_expiry < 0:
                days_html = f'<span class="sev-critical">EXPIRADO ({abs(result.days_until_expiry)} dias atrás)</span>'
            elif result.days_until_expiry < 30:
                days_html = f'<span class="sev-medium">{result.days_until_expiry} dias</span>'
            else:
                days_html = f'<span class="sev-ok">{result.days_until_expiry} dias</span>'

            self_signed_html = (
                '<span class="sev-high">⚠ Sim (auto-assinado)</span>'
                if result.is_self_signed
                else '<span class="sev-ok">✔ Não</span>'
            )

            weak_html = (
                f'<span class="sev-high">⚠ {", ".join(result.weak_protocols)}</span>'
                if result.weak_protocols
                else '<span class="sev-ok">✔ Nenhum detectado</span>'
            )

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### Certificado")
                rows = [
                    ("Protocolo", f"<code>{result.protocol_version}</code>"),
                    ("Expira em", result.cert_expiry),
                    ("Dias até expirar", days_html),
                    ("Auto-assinado", self_signed_html),
                ]
                table_html = (
                    '<table class="seg">'
                    + "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k, v in rows)
                    + "</table>"
                )
                st.markdown(table_html, unsafe_allow_html=True)

            with col2:
                st.markdown("#### Identidade")
                rows2 = [
                    ("Subject", f"<code>{result.subject}</code>"),
                    ("Emissor", f"<code>{result.issuer}</code>"),
                    ("Protocolos fracos", weak_html),
                ]
                table_html2 = (
                    '<table class="seg">'
                    + "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k, v in rows2)
                    + "</table>"
                )
                st.markdown(table_html2, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Página: Scanner — DNS
# ---------------------------------------------------------------------------

elif page == "📋 Scanner — DNS":
    st.title("📋 Análise de Registros DNS")
    st.markdown("Verifica SPF, DMARC, DNSSEC, MX e registros A/AAAA.")

    with st.form("form_dns"):
        domain = st.text_input("Domínio", placeholder="exemplo.com")
        submitted = st.form_submit_button("🔍 Analisar")

    if submitted:
        if not domain.strip():
            st.error("Informe um domínio.")
        else:
            with st.spinner(f"Consultando DNS de **{domain}**..."):
                try:
                    result = check_dns(domain)
                except (ValueError, ConnectionError) as e:
                    st.error(str(e))
                    st.stop()

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### Segurança de E-mail")
                rows = [
                    ("SPF", yn(result.has_spf), result.spf_record or "—"),
                    ("DMARC", yn(result.has_dmarc), result.dmarc_record or "—"),
                    ("DNSSEC", yn(result.has_dnssec), "—"),
                ]
                table_html = (
                    '<table class="seg">'
                    "<thead><tr><th>Registro</th><th>Presente</th><th>Valor</th></tr></thead><tbody>"
                    + "".join(
                        f"<tr><td><b>{r[0]}</b></td><td>{r[1]}</td>"
                        f"<td><code style='font-size:.8rem;word-break:break-all'>{r[2]}</code></td></tr>"
                        for r in rows
                    )
                    + "</tbody></table>"
                )
                st.markdown(table_html, unsafe_allow_html=True)

            with col2:
                st.markdown("#### Resolução")

                if result.mx_records:
                    st.markdown("**MX (servidores de e-mail)**")
                    for mx in result.mx_records:
                        st.code(mx, language=None)
                else:
                    st.markdown("**MX:** <span class='sev-medium'>Nenhum encontrado</span>", unsafe_allow_html=True)

                if result.a_records:
                    st.markdown("**A / AAAA (IPs do domínio)**")
                    for a in result.a_records:
                        st.code(a, language=None)
                else:
                    st.markdown("**A/AAAA:** <span class='sev-high'>Nenhum encontrado</span>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Página: OpSec — DNS Leak
# ---------------------------------------------------------------------------

elif page == "💧 OpSec — DNS Leak":
    st.title("💧 Detecção de DNS Leak")
    st.markdown(
        "Compara a resolução DNS via **DNS-over-HTTPS** (Cloudflare) com o **DNS local** do sistema. "
        "Resultados diferentes podem indicar que consultas DNS estão escapando do túnel VPN."
    )

    with st.form("form_dns_leak"):
        domain = st.text_input("Domínio de teste", value="example.com")
        submitted = st.form_submit_button("🔍 Testar")

    if submitted:
        with st.spinner("Testando..."):
            try:
                result = check_dns_leak(domain)
            except ConnectionError as e:
                st.error(str(e))
                st.stop()

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### DNS-over-HTTPS (Cloudflare 1.1.1.1)")
            if result.doh_ips:
                for ip in result.doh_ips:
                    st.code(ip, language=None)
            else:
                st.warning("Nenhum IP resolvido via DoH.")

        with col2:
            st.markdown("#### DNS local do sistema")
            if result.local_ips:
                for ip in result.local_ips:
                    st.code(ip, language=None)
            else:
                st.warning("Nenhum IP resolvido localmente.")

        st.divider()
        if result.potential_leak:
            st.warning(
                "⚠️ **Possível DNS leak detectado.** "
                "Os IPs resolvidos diferem entre DoH e DNS local. "
                "Verifique as configurações de DNS da sua VPN e considere ativar DNS-over-HTTPS no sistema."
            )
        else:
            st.success("✔ Sem indícios de DNS leak. Os IPs resolvidos são equivalentes.")

# ---------------------------------------------------------------------------
# Página: OpSec — Meu IP
# ---------------------------------------------------------------------------

elif page == "🌍 OpSec — Meu IP":
    st.title("🌍 Informações do IP Público")
    st.markdown(
        "Exibe geolocalização e informações do ISP do seu IP público atual. "
        "Se você estiver usando VPN, mostrará o IP do servidor VPN."
    )

    if st.button("🔍 Verificar meu IP"):
        with st.spinner("Consultando..."):
            try:
                info = get_ip_info()
            except (ConnectionError, RuntimeError) as e:
                st.error(str(e))
                st.stop()

        cards_html = '<div class="info-row">'
        for label, value in [
            ("IP Público", info.ip),
            ("País", info.country),
            ("Região", info.region),
            ("Cidade", info.city),
            ("Fuso Horário", info.timezone),
        ]:
            cards_html += info_card(label, value)
        cards_html += "</div>"
        st.markdown(cards_html, unsafe_allow_html=True)

        st.divider()
        col1, col2 = st.columns(2)
        col1.markdown(f"**ISP:** `{info.isp}`")
        col2.markdown(f"**Organização:** `{info.org}`")

        st.info(
            "💡 Se o IP mostrado for o de um servidor VPN, significa que o túnel está ativo. "
            "Mas lembre-se: VPN não resolve fingerprint de navegador, cookies ou contas logadas."
        )

# ---------------------------------------------------------------------------
# Página: OpSec — Checklist
# ---------------------------------------------------------------------------

elif page == "✅ OpSec — Checklist":
    st.title("✅ Checklist de Segurança Operacional")
    st.markdown(
        "Vetores de risco **reais** — a maioria dos vazamentos de identidade **não** ocorre "
        "na criptografia do túnel, mas em falhas operacionais."
    )

    items = get_checklist()

    # Métricas
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        counts[item.severity] = counts.get(item.severity, 0) + 1

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🔴 Critical", counts["critical"])
    col2.metric("🟠 High", counts["high"])
    col3.metric("🟡 Medium", counts["medium"])
    col4.metric("🔵 Low", counts["low"])

    st.divider()

    # Filtro
    severities = ["Todas", "critical", "high", "medium", "low"]
    filter_sev = st.selectbox("Filtrar por severidade", severities)

    filtered = items if filter_sev == "Todas" else [i for i in items if i.severity == filter_sev]

    rows = []
    for item in filtered:
        sev_html = badge(item.severity, item.severity)
        rows.append(
            f"<tr>"
            f"<td>{sev_html}</td>"
            f"<td><b>{item.category}</b></td>"
            f"<td>{item.risk}</td>"
            f"<td>{item.description}</td>"
            f"<td>{item.mitigation}</td>"
            f"</tr>"
        )

    table_html = (
        '<table class="seg">'
        "<thead><tr>"
        "<th>Sev.</th><th>Categoria</th><th>Risco</th><th>Descrição</th><th>Mitigação</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    st.markdown(table_html, unsafe_allow_html=True)

    st.divider()
    st.markdown("""
    #### Por que VPN não resolve tudo?

    Mesmo com VPN perfeita, você é identificável se:
    - Fizer login em conta pessoal (Google, Facebook, etc.) durante atividade sensível
    - Usar o navegador padrão com fingerprint único (Canvas, WebGL, fontes, plugins)
    - Mantiver cookies de sessões anteriores
    - O WebRTC vazar seu IP real para sites
    - O DNS não estiver resolvendo dentro do túnel

    **A proteção real exige compartimentalização de identidade, não apenas criptografia de rede.**
    """)

# ---------------------------------------------------------------------------
# Página: Relatório Completo
# ---------------------------------------------------------------------------

elif page == "📊 Relatório Completo":
    st.title("📊 Relatório Completo de Segurança")
    st.markdown("Executa todos os módulos de scanning e gera um relatório JSON para download.")

    with st.form("form_report"):
        host = st.text_input("Host", placeholder="exemplo.com")
        col1, col2 = st.columns([1, 3])
        port_end = col1.number_input("Portas até", min_value=1, max_value=65535, value=1024)
        submitted = st.form_submit_button("⚡ Gerar Relatório")

    if submitted:
        if not host.strip():
            st.error("Informe um host.")
        else:
            results: dict = {}
            progress = st.progress(0)
            status = st.empty()

            status.markdown("**1/4** — Escaneando portas...")
            try:
                port_results = scan_ports(host, start=1, end=int(port_end), timeout=0.5)
                results["ports"] = port_results
                open_count = sum(1 for r in port_results if r.state == "open")
                st.success(f"✔ Portas: **{open_count} abertas** de {int(port_end)} verificadas")
            except Exception as e:
                st.warning(f"⚠ Portas: {e}")
                results["ports"] = []
            progress.progress(25)

            status.markdown("**2/4** — Verificando SSL/TLS...")
            try:
                ssl_result = check_ssl(host)
                results["ssl"] = ssl_result
                st.success(f"✔ SSL: {ssl_result.protocol_version} — expira em **{ssl_result.days_until_expiry} dias**")
            except Exception as e:
                st.warning(f"⚠ SSL: {e}")
                results["ssl"] = None
            progress.progress(50)

            status.markdown("**3/4** — Verificando headers HTTP...")
            try:
                http_results = check_headers(f"https://{host}")
                results["http_headers"] = http_results
                missing = sum(1 for r in http_results if not r.present)
                st.success(f"✔ HTTP headers: **{missing} ausentes** de {len(http_results)} verificados")
            except Exception as e:
                st.warning(f"⚠ HTTP headers: {e}")
                results["http_headers"] = []
            progress.progress(75)

            status.markdown("**4/4** — Analisando DNS...")
            try:
                dns_result = check_dns(host)
                results["dns"] = dns_result
                st.success(
                    f"✔ DNS: SPF={'✔' if dns_result.has_spf else '✘'} "
                    f"DMARC={'✔' if dns_result.has_dmarc else '✘'} "
                    f"DNSSEC={'✔' if dns_result.has_dnssec else '✘'}"
                )
            except Exception as e:
                st.warning(f"⚠ DNS: {e}")
                results["dns"] = None
            progress.progress(100)

            status.markdown("**Relatório gerado.**")

            json_str = generate_report(host, results)

            st.divider()
            st.markdown("#### Download")
            filename = f"seginternet_{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            st.download_button(
                label="⬇️ Baixar relatório JSON",
                data=json_str,
                file_name=filename,
                mime="application/json",
                use_container_width=True,
            )

            with st.expander("Visualizar JSON"):
                st.json(json.loads(json_str))
