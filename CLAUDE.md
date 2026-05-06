# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Desenvolvimento local (Windows)

```bash
# Instalar dependências
pip install -r requirements.txt
pip install -e .

# Interface web
python -m streamlit run app.py
# Acesso: http://localhost:8501

# CLI
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
pytest tests/test_ports.py
pytest tests/test_ports.py::TestScanPorts::test_open_port
```

---

## Infraestrutura de produção

### Topologia

```
[Internet] → Cloudflare Edge → cloudflared tunnel → [CT 102: 10.34.34.3:8501]
                                                      (Proxmox: 10.34.34.50, NAT)
```

### IPs e acessos

| Serviço       | IP / Host        | Porta | Acesso                           |
|---------------|------------------|-------|----------------------------------|
| Proxmox host  | 10.34.34.50      | 22    | `ssh root@10.34.34.50`           |
| CT 100        | 10.34.34.5       | —     | nextcloud (produção)             |
| CT 101        | —                | —     | kali VM                          |
| CT 102        | 10.34.34.3       | 22    | `ssh root@10.34.34.3`            |
| seginternet   | 10.34.34.3       | 8501  | interno (exposto via CF Tunnel)  |
| URL pública   | seginternet.rochainf.com.br | 443 | via Cloudflare Tunnel  |

### Serviços no CT 102 (Debian 12)

| Serviço            | Estado       | Comando de controle                          |
|--------------------|--------------|----------------------------------------------|
| seginternet        | ✅ rodando   | `systemctl status seginternet`               |
| cloudflared        | ⏳ aguarda token | `systemctl status cloudflared`           |
| UFW (firewall)     | ✅ ativo     | `ufw status`                                 |
| fail2ban           | ✅ ativo     | `systemctl status fail2ban`                  |
| SSH                | ✅ ativo     | porta 22                                     |

Regras UFW ativas: 22/tcp (SSH), 8501/tcp (interno), default deny incoming.

### Arquivos importantes no CT 102

| Arquivo                                      | Função                             |
|----------------------------------------------|------------------------------------|
| `/opt/seginternet/`                          | Código do projeto                  |
| `/opt/seginternet/.venv/`                    | Virtualenv Python 3.11             |
| `/opt/seginternet.git/`                      | Git bare repo (recebe `git push`)  |
| `/opt/seginternet.git/hooks/post-receive`    | Hook de deploy automático          |
| `/etc/systemd/system/seginternet.service`    | Serviço Streamlit                  |
| `/etc/systemd/system/cloudflared.service`    | Serviço Cloudflare Tunnel          |

---

## Cloudflare Tunnel

O Nextcloud (CT 100) usa abordagem **token** (não config.yml):
```
/usr/bin/cloudflared --no-autoupdate tunnel run --token eyJ...
```

O seginternet (CT 102) usa o mesmo padrão. O token é obtido em:
**Cloudflare Zero Trust → Networks → Tunnels → Create a tunnel → Cloudflared**

Após obter o token, inserir no CT 102:
```bash
# Editar /etc/systemd/system/cloudflared.service
# Substituir CLOUDFLARE_TOKEN_AQUI pelo token real
ssh root@10.34.34.3
sed -i 's/CLOUDFLARE_TOKEN_AQUI/<TOKEN>/' /etc/systemd/system/cloudflared.service
systemctl daemon-reload
systemctl enable --now cloudflared
systemctl status cloudflared
```

No dashboard Cloudflare, adicionar Public Hostname:
- Subdomain: `seginternet` | Domain: `rochainf.com.br`
- Service: `http://localhost:8501`

---

## Fluxo de atualização (deploy)

```bash
# Na máquina local — após qualquer mudança no código:
git add -A
git commit -m "descrição da mudança"
git push lxc master
# O hook post-receive no CT 102 faz pip install + systemctl restart automaticamente
```

O remote `lxc` aponta para `ssh://root@10.34.34.3/opt/seginternet.git`.

---

## Comandos úteis no CT 102

```bash
# Conectar
ssh root@10.34.34.3

# Logs do Streamlit em tempo real
journalctl -u seginternet -f

# Reiniciar o app
systemctl restart seginternet

# Logs do tunnel
journalctl -u cloudflared -f

# Verificar porta
ss -tlnp | grep 8501

# Ver processos Python
pgrep -a python

# Uso de disco
df -h

# Status geral
systemctl status seginternet cloudflared ufw fail2ban
```

---

## Erros encontrados durante o deploy

| Erro | Causa | Solução aplicada |
|------|-------|-----------------|
| `pip install -e .` falhou (editable install) | `pyproject.toml` usava `setuptools.backends.legacy:build` incompatível com Python 3.14 | Corrigido para `setuptools.build_meta` |
| `streamlit: command not found` no Bash | Streamlit instalado no PATH do Windows, não no Bash (Git Bash) | Usar `python -m streamlit run app.py` |
| Heredoc em `pct exec` não funcionou | Caracteres especiais/aspas corrompem o comando via `pct exec -- bash -c` | Reescrito via SFTP (paramiko) direto |
| `seginternet.service` masked | Arquivo criado vazio pelo heredoc falho, systemd mascarou | Reescrito via SFTP + `systemctl unmask` |
| `Port 8501 is not available` no journal | Segunda instância tentou subir enquanto a primeira ainda estava ativa (restart) | Normal — primeira instância rodando corretamente |

---

## Arquitetura do código

Entry point web: `app.py` (Streamlit). Entry point CLI: `src/seginternet/cli.py` (Typer).

### Módulos

**`scanner/`** — análise passiva/não-intrusiva:
- `ports.py` — scan TCP paralelo com `ThreadPoolExecutor(max_workers=100)`
- `http_headers.py` — verifica 7 headers de segurança HTTP via `httpx`
- `ssl_check.py` — certificado, validade, protocolos fracos via `ssl` stdlib
- `dns_check.py` — SPF, DMARC, DNSSEC, MX via `dnspython`

**`opsec/`** — vetores de risco além do túnel:
- `dns_leak.py` — compara DoH (Cloudflare 1.1.1.1) com DNS local
- `ip_info.py` — geolocalização via `ipapi.co`
- `checklist.py` — 10 itens estáticos (fingerprint, WebRTC, contas, etc.)

**`local/`** — verificação da máquina atual:
- `machine_check.py` — cross-platform (Windows: netsh/Defender; Linux: UFW/ClamAV/fail2ban)

**`reporter/report.py`** — serializa resultados para JSON com timestamp e contagem de severidades.

### Tipos de retorno

Todos os módulos retornam `dataclass`es. O reporter usa `dataclasses.asdict` para serialização.

### Severidades

`critical` → `high` → `medium` → `low`. Ausência de HSTS/CSP = high; fingerprint/correlação de contas = critical.
