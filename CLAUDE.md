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

## Estado atual do deploy (2026-05-06) — PRODUÇÃO ✅

Tudo rodando. Site público: **https://seginternet.rochainf.com.br**

| Serviço       | Estado   | Observação                              |
|---------------|----------|-----------------------------------------|
| seginternet   | ✅ ativo  | porta 8501, systemd                    |
| cloudflared   | ✅ ativo  | tunnel conectado, gru21                |
| UFW           | ✅ ativo  | 22/tcp + 8501/tcp                      |
| fail2ban      | ✅ ativo  | —                                      |

---

## Infraestrutura de produção

### Topologia

```
[Internet] → Cloudflare Edge → cloudflared tunnel → [CT 102: 10.34.34.3:8501]
                                                      (Proxmox: 10.34.34.50, NAT)
```

### IPs e acessos

| Serviço       | IP / Host                   | Porta | Acesso                          |
|---------------|-----------------------------|-------|---------------------------------|
| Proxmox host  | 10.34.34.50                 | 22    | `ssh root@10.34.34.50`          |
| CT 100        | 10.34.34.5                  | —     | nextcloud (produção)            |
| CT 101        | —                           | —     | kali VM                         |
| CT 102        | 10.34.34.3                  | 22    | `ssh root@10.34.34.3`           |
| seginternet   | 10.34.34.3                  | 8501  | interno (exposto via CF Tunnel) |
| URL pública   | seginternet.rochainf.com.br | 443   | via Cloudflare Tunnel           |

Senha root CT 102 e Proxmox: `A1b15270@`

### Arquivos importantes no CT 102

| Arquivo                                      | Função                                        |
|----------------------------------------------|-----------------------------------------------|
| `/opt/seginternet/`                          | Código do projeto (deploy via SFTP/paramiko)  |
| `/opt/seginternet/.venv/`                    | Virtualenv Python 3.11                        |
| `/opt/seginternet.git/`                      | Git bare repo (recebe `git push lxc`)         |
| `/opt/seginternet.git/hooks/post-receive`    | Hook de deploy automático                     |
| `/etc/systemd/system/seginternet.service`    | Serviço Streamlit (inclui APP_USER e hash)    |
| `/etc/systemd/system/cloudflared.service`    | Serviço Cloudflare Tunnel (inclui token)      |

### seginternet.service (conteúdo atual)

```ini
[Unit]
Description=seginternet — análise de segurança de internet
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/seginternet
Environment=APP_USER=admin
Environment=APP_PASSWORD_HASH=a35827e542fb38056e235d353223018c87f6255363272b0055f672e608a2e249
ExecStart=/opt/seginternet/.venv/bin/python -m streamlit run app.py --server.port 8501 --server.address 0.0.0.0 --server.headless true
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### cloudflared.service

Usa abordagem token (não config.yml):
```
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel --protocol http2 run --token <TOKEN>
```
Token atual configurado e funcionando. Public Hostname: `seginternet.rochainf.com.br → http://localhost:8501`

---

## Credenciais de acesso ao app

| Campo   | Valor                    |
|---------|--------------------------|
| Usuário | `admin`                  |
| Senha   | `PO0un9_59H0jx472dAqfwg` |

Hash SHA-256 da senha: `a35827e542fb38056e235d353223018c87f6255363272b0055f672e608a2e249`

Para trocar a senha:
```bash
# 1. Gerar novo hash localmente
python -c "import hashlib; print(hashlib.sha256(b'NOVA_SENHA').hexdigest())"

# 2. Atualizar no CT 102
ssh root@10.34.34.3
sed -i 's|APP_PASSWORD_HASH=.*|APP_PASSWORD_HASH=<NOVO_HASH>|' /etc/systemd/system/seginternet.service
systemctl daemon-reload && systemctl restart seginternet
```

---

## Repositório GitHub

URL: **https://github.com/PgSa9XkUDPyR/seginternet**

O token GitHub usado para criar o repo pertence ao usuário `PgSa9XkUDPyR` (não `rochainf`).
Se quiser transferir para a conta principal: *GitHub → Settings → Transfer repository*.

### Remotes configurados localmente

| Remote | URL                                                      |
|--------|----------------------------------------------------------|
| `lxc`  | `ssh://root@10.34.34.3/opt/seginternet.git`              |
| `origin` | `https://github.com/PgSa9XkUDPyR/seginternet.git`     |

---

## Fluxo de atualização (deploy)

```bash
# Após qualquer mudança no código:
git add -A
git commit -m "descrição da mudança"
git push origin master   # → GitHub (fonte de verdade)
git push lxc master      # → CT 102 (deploy automático via hook post-receive)
```

> **Atenção:** `git push lxc master` requer chave SSH configurada para root@10.34.34.3.
> Se falhar por auth, usar deploy via paramiko (Python) — ver seção abaixo.

### Deploy via paramiko (fallback quando SSH sem chave falha)

```python
import paramiko, pathlib

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('10.34.34.3', username='root', password='A1b15270@', timeout=15)

sftp = client.open_sftp()
for remote, local in {
    '/opt/seginternet/app.py': 'app.py',
    '/opt/seginternet/src/seginternet/opsec/ip_info.py': 'src/seginternet/opsec/ip_info.py',
}.items():
    with sftp.open(remote, 'w') as f:
        f.write(pathlib.Path(local).read_text(encoding='utf-8'))
sftp.close()

client.exec_command('systemctl restart seginternet')
client.close()
```

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

# Matar processo preso na porta 8501 (se restart falhar)
pkill -f streamlit; sleep 2; systemctl start seginternet

# Uso de disco
df -h

# Status geral
systemctl status seginternet cloudflared ufw fail2ban
```

---

## Erros encontrados

| Erro | Causa | Solução |
|------|-------|---------|
| `pip install -e .` falhou | `pyproject.toml` com `setuptools.backends.legacy:build` incompatível com Python 3.14 | Corrigido para `setuptools.build_meta` |
| `streamlit: command not found` no Bash | Streamlit no PATH do Windows, não no Git Bash | Usar `python -m streamlit run app.py` |
| Heredoc em `pct exec` corrompeu arquivo | Aspas/caracteres especiais via `pct exec -- bash -c` | Reescrever arquivos via SFTP (paramiko) |
| `seginternet.service` masked | Arquivo criado vazio pelo heredoc falho | Reescrever via SFTP + `systemctl unmask` |
| `Port 8501 is not available` no restart | Segunda instância sobe antes da primeira liberar a porta | Fazer `pkill -f streamlit` antes de `systemctl start` |
| `git push lxc master` falha com `Permission denied` | SSH para root@10.34.34.3 requer chave (sem senha por padrão) | Usar deploy via paramiko como fallback |
| `fuser` não encontrado no CT 102 | `psmisc` não instalado no Debian 12 mínimo | Usar `pkill -f streamlit` no lugar |

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
- `ip_info.py` — geolocalização via `ipapi.co`. Aceita `ip` opcional: `get_ip_info(ip="1.2.3.4")`
- `checklist.py` — 10 itens estáticos (fingerprint, WebRTC, contas, etc.)

**`local/`** — verificação da máquina atual:
- `machine_check.py` — cross-platform (Windows: netsh/Defender; Linux: UFW/ClamAV/fail2ban)

**`reporter/report.py`** — serializa resultados para JSON com timestamp e contagem de severidades.

### Tipos de retorno

Todos os módulos retornam `dataclasses`. O reporter usa `dataclasses.asdict` para serialização.

### Severidades

`critical` → `high` → `medium` → `low`. Ausência de HSTS/CSP = high; fingerprint/correlação de contas = critical.

---

## Funcionalidades adicionadas (sessão 2026-05-06)

### Autenticação (`app.py`)
- Login/senha obrigatório via `st.session_state`
- Credenciais em variáveis de ambiente no systemd (`APP_USER`, `APP_PASSWORD_HASH`)
- Hash SHA-256 sem salt — adequado para uso pessoal
- Função: `_login_gate()` — bloqueia toda a UI se não autenticado

### Bloqueio de IPs privados no scanner
- Scanner de Portas TCP bloqueia IPs privados/loopback/link-local
- Usa `ipaddress.ip_address(resolved).is_private` antes de escanear
- Protege a rede interna (10.34.34.x) de ser escaneada por visitantes

### Página: Verificação da Máquina — aviso de modo servidor
- Detecta `platform.system() != "Windows"` e exibe banner informando que analisa CT 102, não a máquina do visitante

### Página: OpSec — Meu IP (corrigida)
- Usa header `CF-Connecting-IP` do Cloudflare para mostrar IP real do visitante
- Função: `_get_visitor_ip()` — lê `st.context.headers`
- `get_ip_info(ip=visitor_ip)` aceita IP externo agora

### Página nova: Verificação Remota (`🔎`)
- IP real do visitante + geolocalização (ipapi.co com IP do CF header)
- WebRTC leak test via `st.components.v1.html` com JS puro (detecta vazamento de IP real pelo browser)
- Análise rápida de host externo (portas + SSL + DNS) em formulário único

### Página nova: Instalar Localmente (`💻`)
- Instruções de instalação via `git clone` do GitHub
- Download de `setup_windows.ps1` e `setup_linux.sh`
- Scripts clonam do GitHub, instalam Python/Git se necessário, criam venv e iniciam o app
- **Não serve mais o ZIP do código-fonte** (removido por segurança)

---

## Pendências / próximos passos

- [ ] Configurar chave SSH local para `root@10.34.34.3` (eliminar necessidade de paramiko para deploy)
- [ ] Verificar se o repositório GitHub deve ser transferido para a conta principal (`rochainf`)
- [ ] Revogar token GitHub usado para criar o repo (gerado em github.com/settings/tokens) após confirmar que não é mais necessário
- [ ] Avaliar adicionar `README.md` ao repositório GitHub
- [ ] Testar instalação local via `setup_windows.ps1` em máquina limpa
