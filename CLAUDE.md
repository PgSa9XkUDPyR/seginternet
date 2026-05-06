# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Comandos

```bash
# Instalar dependências
pip install -e ".[dev]"
# ou
pip install -r requirements.txt -r requirements-dev.txt

# Interface web (Streamlit)
streamlit run app.py

# Rodar a ferramenta via CLI
seginternet --help
seginternet scan ports <host>
seginternet scan http <url>
seginternet scan ssl <host>
seginternet scan dns <domain>
seginternet opsec dns-leak
seginternet opsec ip
seginternet opsec checklist
seginternet report <host> --output report.json

# Testes
pytest
pytest tests/test_ports.py          # arquivo específico
pytest tests/test_ports.py::TestScanPorts::test_open_port  # teste único
```

## Arquitetura

Ferramenta CLI de análise de segurança de internet. Entry point: `src/seginternet/cli.py` com dois grupos de subcomandos Typer — `scan` e `opsec`.

### Módulos

**`scanner/`** — análise passiva/não-intrusiva de hosts:
- `ports.py` — scan TCP com `ThreadPoolExecutor(max_workers=100)` + `socket.connect_ex`
- `http_headers.py` — verifica 7 headers de segurança HTTP via `httpx`
- `ssl_check.py` — validade de certificado, protocolo, protocolos fracos (TLS 1.0/1.1) via `ssl` stdlib
- `dns_check.py` — SPF, DMARC, DNSSEC, MX via `dnspython`

**`opsec/`** — análise operacional (vetores de risco além do túnel criptografado):
- `dns_leak.py` — compara DNS-over-HTTPS (Cloudflare 1.1.1.1) com DNS local do sistema
- `ip_info.py` — geolocalização e ISP do IP público via `ipapi.co`
- `checklist.py` — checklist estática com 10 vetores de risco (fingerprint, WebRTC, correlação de contas, etc.)

**`reporter/report.py`** — serializa todos os resultados para JSON com timestamp e contagem de severidades.

### Tipos de retorno

Todos os módulos retornam `dataclass`es (`PortResult`, `HeaderResult`, `SSLResult`, `DNSResult`, etc.). O reporter usa `dataclasses.asdict` para serialização.

### Severidades

`critical` (vermelho bold) → `high` (vermelho) → `medium` (amarelo) → `low` (azul). Ausência de HSTS/CSP = high; correlação de contas/fingerprint = critical.
