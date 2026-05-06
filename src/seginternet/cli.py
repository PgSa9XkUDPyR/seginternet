"""Interface CLI principal — seginternet."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich import box

from seginternet.scanner.ports import scan_ports, PortResult
from seginternet.scanner.http_headers import check_headers, HeaderResult
from seginternet.scanner.ssl_check import check_ssl
from seginternet.scanner.dns_check import check_dns
from seginternet.opsec.dns_leak import check_dns_leak
from seginternet.opsec.ip_info import get_ip_info
from seginternet.opsec.checklist import get_checklist
from seginternet.reporter.report import generate_report

console = Console()

app = typer.Typer(
    name="seginternet",
    help="Ferramenta CLI de análise de segurança de internet.",
    add_completion=False,
)

scan_app = typer.Typer(help="Comandos de scanning de host/URL.")
opsec_app = typer.Typer(help="Comandos de análise operacional de segurança.")

app.add_typer(scan_app, name="scan")
app.add_typer(opsec_app, name="opsec")


# ---------------------------------------------------------------------------
# Helpers de formatação
# ---------------------------------------------------------------------------

_SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
}


def _severity_badge(severity: str) -> str:
    style = _SEVERITY_STYLE.get(severity.lower(), "white")
    return f"[{style}]{severity.upper()}[/{style}]"


# ---------------------------------------------------------------------------
# scan ports
# ---------------------------------------------------------------------------

@scan_app.command("ports")
def cmd_scan_ports(
    host: str = typer.Argument(..., help="Host ou IP a escanear."),
    start_port: int = typer.Option(1, "--start-port", help="Porta inicial."),
    end_port: int = typer.Option(1024, "--end-port", help="Porta final (inclusive)."),
    timeout: float = typer.Option(1.0, "--timeout", help="Timeout por porta em segundos."),
) -> None:
    """Escaneia portas TCP abertas em HOST."""
    console.print(
        f"[bold]Escaneando portas {start_port}-{end_port} em[/bold] [cyan]{host}[/cyan]..."
    )

    try:
        results = scan_ports(host, start=start_port, end=end_port, timeout=timeout)
    except (ValueError, ConnectionError) as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise typer.Exit(1)

    open_ports = [r for r in results if r.state == "open"]

    table = Table(title=f"Portas abertas em {host}", box=box.ROUNDED)
    table.add_column("Porta", style="bold", justify="right")
    table.add_column("Serviço")
    table.add_column("Estado")

    for r in open_ports:
        table.add_row(str(r.port), r.service, "[green]aberta[/green]")

    if open_ports:
        console.print(table)
    else:
        console.print("[green]Nenhuma porta aberta encontrada no intervalo.[/green]")

    closed_count = len(results) - len(open_ports)
    console.print(
        f"[dim]Total: {len(results)} portas verificadas — "
        f"[green]{len(open_ports)} abertas[/green], "
        f"[dim]{closed_count} fechadas[/dim][/dim]"
    )


# ---------------------------------------------------------------------------
# scan http
# ---------------------------------------------------------------------------

@scan_app.command("http")
def cmd_scan_http(
    url: str = typer.Argument(..., help="URL a verificar (http:// ou https://)."),
) -> None:
    """Analisa os cabeçalhos HTTP de segurança de URL."""
    console.print(f"[bold]Verificando cabeçalhos de segurança:[/bold] [cyan]{url}[/cyan]")

    try:
        results = check_headers(url)
    except Exception as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise typer.Exit(1)

    table = Table(title="Cabeçalhos HTTP de Segurança", box=box.ROUNDED)
    table.add_column("Cabeçalho")
    table.add_column("Presente")
    table.add_column("Valor", overflow="fold", max_width=60)
    table.add_column("Severidade")

    for r in results:
        present_str = "[green]Sim[/green]" if r.present else "[red]Não[/red]"
        value_str = r.value if r.value else "[dim]—[/dim]"
        sev_str = "[dim]OK[/dim]" if r.present else _severity_badge(r.severity)
        table.add_row(r.header, present_str, value_str, sev_str)

    console.print(table)


# ---------------------------------------------------------------------------
# scan ssl
# ---------------------------------------------------------------------------

@scan_app.command("ssl")
def cmd_scan_ssl(
    host: str = typer.Argument(..., help="Host a verificar."),
    port: int = typer.Option(443, "--port", help="Porta TLS."),
) -> None:
    """Verifica a configuração SSL/TLS de HOST."""
    console.print(
        f"[bold]Verificando SSL/TLS:[/bold] [cyan]{host}:{port}[/cyan]"
    )

    try:
        result = check_ssl(host, port=port)
    except ConnectionError as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise typer.Exit(1)

    expiry_style = (
        "red" if result.days_until_expiry < 0
        else "yellow" if result.days_until_expiry < 30
        else "green"
    )

    self_signed_str = (
        "[red]Sim (auto-assinado)[/red]"
        if result.is_self_signed
        else "[green]Não[/green]"
    )

    weak_str = (
        f"[red]{', '.join(result.weak_protocols)}[/red]"
        if result.weak_protocols
        else "[green]Nenhum[/green]"
    )

    table = Table(title=f"SSL/TLS — {host}:{port}", box=box.ROUNDED)
    table.add_column("Campo", style="bold")
    table.add_column("Valor")

    table.add_row("Protocolo", result.protocol_version)
    table.add_row("Expiração", result.cert_expiry)
    table.add_row(
        "Dias até expirar",
        f"[{expiry_style}]{result.days_until_expiry}[/{expiry_style}]",
    )
    table.add_row("Emissor", result.issuer)
    table.add_row("Subject", result.subject)
    table.add_row("Auto-assinado", self_signed_str)
    table.add_row("Protocolos fracos detectados", weak_str)

    console.print(table)


# ---------------------------------------------------------------------------
# scan dns
# ---------------------------------------------------------------------------

@scan_app.command("dns")
def cmd_scan_dns(
    domain: str = typer.Argument(..., help="Domínio a analisar."),
) -> None:
    """Analisa os registros DNS de segurança de DOMAIN."""
    console.print(f"[bold]Analisando DNS de:[/bold] [cyan]{domain}[/cyan]")

    try:
        result = check_dns(domain)
    except (ValueError, ConnectionError) as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise typer.Exit(1)

    def _yn(value: bool) -> str:
        return "[green]Sim[/green]" if value else "[red]Não[/red]"

    table = Table(title=f"DNS — {domain}", box=box.ROUNDED)
    table.add_column("Registro", style="bold")
    table.add_column("Presente")
    table.add_column("Valor", overflow="fold", max_width=70)

    table.add_row("SPF", _yn(result.has_spf), result.spf_record or "[dim]—[/dim]")
    table.add_row("DMARC", _yn(result.has_dmarc), result.dmarc_record or "[dim]—[/dim]")
    table.add_row("DNSSEC", _yn(result.has_dnssec), "[dim]—[/dim]")
    table.add_row(
        "MX",
        _yn(bool(result.mx_records)),
        "\n".join(result.mx_records) if result.mx_records else "[dim]—[/dim]",
    )
    table.add_row(
        "A/AAAA",
        _yn(bool(result.a_records)),
        "\n".join(result.a_records) if result.a_records else "[dim]—[/dim]",
    )

    console.print(table)


# ---------------------------------------------------------------------------
# opsec dns-leak
# ---------------------------------------------------------------------------

@opsec_app.command("dns-leak")
def cmd_dns_leak(
    domain: str = typer.Option("example.com", "--domain", help="Domínio de teste."),
) -> None:
    """Testa possível vazamento de DNS comparando DoH (Cloudflare) com DNS local."""
    console.print(f"[bold]Testando DNS leak para:[/bold] [cyan]{domain}[/cyan]")

    try:
        result = check_dns_leak(domain)
    except ConnectionError as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise typer.Exit(1)

    table = Table(title=f"DNS Leak — {domain}", box=box.ROUNDED)
    table.add_column("Fonte", style="bold")
    table.add_column("IPs resolvidos")

    table.add_row("DNS-over-HTTPS (Cloudflare)", ", ".join(result.doh_ips) or "[dim]nenhum[/dim]")
    table.add_row("DNS local do sistema", ", ".join(result.local_ips) or "[dim]nenhum[/dim]")

    console.print(table)

    if result.potential_leak:
        console.print(
            "[yellow]Aviso:[/yellow] Os IPs diferem — possível vazamento de DNS detectado. "
            "Verifique sua configuração de VPN/DNS."
        )
    else:
        console.print("[green]OK:[/green] Sem indícios de vazamento de DNS.")


# ---------------------------------------------------------------------------
# opsec ip
# ---------------------------------------------------------------------------

@opsec_app.command("ip")
def cmd_ip_info() -> None:
    """Exibe informações sobre o IP público atual."""
    console.print("[bold]Consultando IP público...[/bold]")

    try:
        info = get_ip_info()
    except (ConnectionError, RuntimeError) as exc:
        console.print(f"[red]Erro:[/red] {exc}")
        raise typer.Exit(1)

    table = Table(title="Informações do IP Público", box=box.ROUNDED)
    table.add_column("Campo", style="bold")
    table.add_column("Valor")

    table.add_row("IP", info.ip)
    table.add_row("País", info.country)
    table.add_row("Região", info.region)
    table.add_row("Cidade", info.city)
    table.add_row("ISP", info.isp)
    table.add_row("Organização", info.org)
    table.add_row("Fuso horário", info.timezone)

    console.print(table)


# ---------------------------------------------------------------------------
# opsec checklist
# ---------------------------------------------------------------------------

@opsec_app.command("checklist")
def cmd_checklist() -> None:
    """Exibe checklist de OpSec com vetores reais de risco."""
    items = get_checklist()

    table = Table(
        title="Checklist de Segurança Operacional (OpSec)",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Categoria", style="bold", no_wrap=True)
    table.add_column("Risco")
    table.add_column("Descrição", overflow="fold", max_width=45)
    table.add_column("Mitigação", overflow="fold", max_width=45)
    table.add_column("Severidade", no_wrap=True)

    for item in items:
        table.add_row(
            item.category,
            item.risk,
            item.description,
            item.mitigation,
            _severity_badge(item.severity),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@app.command("report")
def cmd_report(
    host: str = typer.Argument(..., help="Host a analisar para o relatório completo."),
    output: str = typer.Option("report.json", "--output", "-o", help="Arquivo de saída."),
) -> None:
    """Gera relatório consolidado de segurança para HOST."""
    console.print(f"[bold]Gerando relatório para:[/bold] [cyan]{host}[/cyan]")

    results: dict = {}

    with console.status("Escaneando portas (1-1024)..."):
        try:
            port_results = scan_ports(host, start=1, end=1024, timeout=0.5)
            results["ports"] = port_results
            open_count = sum(1 for r in port_results if r.state == "open")
            console.print(f"  [green]✓[/green] Portas: {open_count} abertas de 1024 verificadas")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow] Portas: {exc}")
            results["ports"] = []

    with console.status("Verificando SSL/TLS..."):
        try:
            ssl_result = check_ssl(host)
            results["ssl"] = ssl_result
            console.print(f"  [green]✓[/green] SSL: {ssl_result.protocol_version}, expira em {ssl_result.days_until_expiry} dias")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow] SSL: {exc}")
            results["ssl"] = None

    with console.status("Verificando cabeçalhos HTTP..."):
        try:
            http_results = check_headers(f"https://{host}")
            results["http_headers"] = http_results
            missing = sum(1 for r in http_results if not r.present)
            console.print(f"  [green]✓[/green] HTTP headers: {missing} ausentes de {len(http_results)} verificados")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow] HTTP headers: {exc}")
            results["http_headers"] = []

    with console.status("Analisando DNS..."):
        try:
            dns_result = check_dns(host)
            results["dns"] = dns_result
            console.print(f"  [green]✓[/green] DNS: SPF={dns_result.has_spf}, DMARC={dns_result.has_dmarc}, DNSSEC={dns_result.has_dnssec}")
        except Exception as exc:
            console.print(f"  [yellow]⚠[/yellow] DNS: {exc}")
            results["dns"] = None

    json_str = generate_report(host, results)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json_str, encoding="utf-8")

    console.print(f"\n[green bold]Relatório salvo em:[/green bold] {output_path.resolve()}")


if __name__ == "__main__":
    app()
