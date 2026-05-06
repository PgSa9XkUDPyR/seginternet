# Deploy — seginternet.rochainf.com.br

Guia completo para provisionar o ambiente e publicar o projeto `seginternet` em produção usando Proxmox LXC + Cloudflare Tunnel.

---

## Pré-requisitos

- Proxmox instalado e acessível via SSH ou console web
- Template Ubuntu 24.04 baixado no Proxmox (`local:vztmpl`)
- Domínio `rochainf.com.br` gerenciado pelo Cloudflare (nameservers apontando para CF)
- Chave SSH local configurada (`~/.ssh/id_ed25519` ou `~/.ssh/id_rsa`)
- Git instalado na máquina local

---

## Passo 1 — Criar o LXC no Proxmox

### Opção A — Script automatizado (recomendado)

Copie o script para o host Proxmox e execute:

```bash
# Na sua máquina local
scp deploy/01-proxmox-create-lxc.sh root@<IP_DO_PROXMOX>:/root/

# No host Proxmox (via SSH ou console)
ssh root@<IP_DO_PROXMOX>
bash /root/01-proxmox-create-lxc.sh
```

O script cria o container com CT ID 200. Edite a variável `CT_ID` no topo do script para usar outro ID se necessário.

Ao final, o script exibe o **IP obtido via DHCP** — anote-o.

### Opção B — Interface web do Proxmox (passo a passo)

1. Acesse `https://<IP_PROXMOX>:8006`
2. Clique em **Create CT** no canto superior direito
3. Preencha os campos:

| Campo | Valor |
|---|---|
| Node | seu-node |
| CT ID | 200 |
| Hostname | seginternet |
| Password | (senha temporária) |
| Template | ubuntu-24.04-standard_24.04-2_amd64.tar.zst |
| Disk storage | local-lvm |
| Disk size | 8 GB |
| Cores | 2 |
| Memory | 1024 MB |
| Swap | 512 MB |
| Network - Bridge | vmbr0 |
| Network - IP | DHCP |
| Unprivileged | Marcado |

4. Em **Options**, habilite: **Nesting** = Yes
5. Clique em **Finish** e depois em **Start**
6. Acesse o console do container e anote o IP: `ip addr show eth0`

---

## Passo 2 — Configurar o LXC

Copie os arquivos de deploy para dentro do container e execute o script de setup.

### Copiar os arquivos (do Windows para o LXC)

```bash
# No Git Bash ou WSL — substitua 192.168.1.X pelo IP real do LXC
LXC_IP=192.168.1.X

# Copiar todos os arquivos de deploy
scp -r deploy/ root@${LXC_IP}:/root/deploy/
```

### Executar o setup dentro do LXC

```bash
ssh root@${LXC_IP}
bash /root/deploy/02-setup-lxc.sh
```

O script executa automaticamente:
- Atualização do sistema
- Instalação de dependências (Python 3, git, ufw, fail2ban, cloudflared)
- Criação do usuário `seginternet`
- Configuração do firewall (UFW)
- Criação do git bare repo com hook post-receive
- Criação do virtualenv Python em `/opt/seginternet/.venv`
- Instalação dos serviços systemd

---

## Passo 3 — Configurar chave SSH

Execute na sua máquina local para copiar a chave pública para o LXC:

```bash
# No Git Bash ou WSL
bash deploy/add-ssh-key.sh 192.168.1.X
```

Será solicitada a senha root do container (definida em `01-proxmox-create-lxc.sh`).

Após isso, o acesso será feito exclusivamente por chave — a autenticação por senha fica desabilitada.

Teste o acesso:
```bash
ssh root@192.168.1.X
ssh seginternet@192.168.1.X
```

---

## Passo 4 — Configurar Cloudflare Tunnel

Execute os comandos abaixo **dentro do LXC** (via SSH como root):

```bash
# 1. Autenticar com o Cloudflare (abre URL no navegador)
cloudflared tunnel login

# 2. Criar o tunnel
cloudflared tunnel create seginternet
# O comando exibe algo como:
# Created tunnel seginternet with id a1b2c3d4-e5f6-7890-abcd-ef1234567890
# Anote esse UUID (Tunnel ID)

# 3. Editar a configuração do tunnel — substitua TUNNEL_ID_AQUI pelo UUID real
nano /etc/cloudflared/config.yml
# Substitua as duas ocorrências de TUNNEL_ID_AQUI pelo UUID
# Exemplo:
#   tunnel: a1b2c3d4-e5f6-7890-abcd-ef1234567890
#   credentials-file: /root/.cloudflared/a1b2c3d4-e5f6-7890-abcd-ef1234567890.json

# 4. Criar o registro DNS no Cloudflare (CNAME automático)
cloudflared tunnel route dns seginternet seginternet.rochainf.com.br

# 5. Habilitar e iniciar o serviço
systemctl enable cloudflared
systemctl start cloudflared

# 6. Verificar
cloudflared tunnel info seginternet
systemctl status cloudflared
```

---

## Passo 5 — Configurar git remote local e fazer o primeiro deploy

Execute na sua máquina local, dentro da pasta do projeto:

```bash
# Inicializar o repositório git (se ainda não for um repo)
git init

# Adicionar todos os arquivos
git add -A
git commit -m "initial commit"

# Adicionar o remote apontando para o LXC
git remote add lxc ssh://root@192.168.1.X/opt/seginternet.git

# Primeiro push (dispara o hook post-receive que faz o deploy)
git push lxc main
```

O hook `post-receive` automaticamente:
1. Faz checkout do código em `/opt/seginternet`
2. Instala as dependências do `requirements.txt`
3. Reinicia o serviço `seginternet`

---

## Passo 6 — Verificar

```bash
# Status dos serviços
systemctl status seginternet
systemctl status cloudflared

# Testar o app localmente (dentro do LXC)
curl -s http://localhost:8501/healthz

# Ver logs do Streamlit
journalctl -u seginternet -n 50 -f

# Ver logs do tunnel
journalctl -u cloudflared -n 50 -f

# Testar o acesso externo (da sua máquina local)
curl -I https://seginternet.rochainf.com.br
```

---

## Atualizar o projeto (fluxo normal)

### Usando o script update.sh (recomendado)

```bash
# No Git Bash ou WSL
bash deploy/update.sh 192.168.1.X

# Ou com variável de ambiente
export LXC_IP=192.168.1.X
bash deploy/update.sh
```

O script detecta mudanças, cria o commit automaticamente e faz o push.

### Manualmente

```bash
git add -A
git commit -m "descrição da mudança"
git push lxc main
```

---

## Acesso SSH

```bash
# Como root (deploy e administração)
ssh root@192.168.1.X

# Como usuário da aplicação
ssh seginternet@192.168.1.X

# Via Proxmox (sem precisar de IP, útil se o IP mudar)
pct enter 200
```

Para usar um hostname ao invés do IP, adicione ao `~/.ssh/config` local:

```
Host seginternet-lxc
    HostName 192.168.1.X
    User root
    IdentityFile ~/.ssh/id_ed25519
```

Depois: `ssh seginternet-lxc`

---

## Comandos úteis no LXC

```bash
# Ver status dos serviços
systemctl status seginternet
systemctl status cloudflared

# Reiniciar serviços
systemctl restart seginternet
systemctl restart cloudflared

# Logs em tempo real
journalctl -u seginternet -f
journalctl -u cloudflared -f

# Logs das últimas 100 linhas
journalctl -u seginternet -n 100
journalctl -u cloudflared -n 100

# Ver processos Python rodando
ps aux | grep streamlit

# Verificar porta 8501
ss -tlnp | grep 8501

# Testar app internamente
curl http://localhost:8501

# Verificar espaço em disco
df -h

# Verificar uso de memória
free -h

# Atualizar cloudflared manualmente
curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cf.deb
dpkg -i /tmp/cf.deb && systemctl restart cloudflared

# Ver informações do tunnel
cloudflared tunnel info seginternet
cloudflared tunnel list
```

---

## Estrutura de diretórios no LXC

```
/opt/seginternet/          # Diretório da aplicação (owner: seginternet)
/opt/seginternet/.venv/    # Virtualenv Python
/opt/seginternet.git/      # Git bare repo (para git push)
/opt/seginternet.git/hooks/post-receive  # Hook de deploy automático
/etc/cloudflared/config.yml              # Configuração do tunnel
/root/.cloudflared/                      # Credenciais do tunnel
/etc/systemd/system/seginternet.service  # Serviço Streamlit
/etc/systemd/system/cloudflared.service  # Serviço Cloudflare Tunnel
```

---

## Solução de problemas

### App não inicia após deploy

```bash
# Ver log de erros detalhado
journalctl -u seginternet -n 100 --no-pager

# Testar manualmente (como usuário seginternet)
su - seginternet
cd /opt/seginternet
.venv/bin/python -m streamlit run app.py --server.port 8501 --server.headless true
```

### Cloudflare Tunnel não conecta

```bash
# Verificar configuração
cat /etc/cloudflared/config.yml

# Testar o tunnel manualmente
cloudflared tunnel --config /etc/cloudflared/config.yml run

# Verificar se o arquivo de credenciais existe
ls -la /root/.cloudflared/

# Re-autenticar se necessário
cloudflared tunnel login
```

### Erro de permissão no git push

```bash
# No LXC, verificar permissões do bare repo
ls -la /opt/seginternet.git/hooks/
chmod +x /opt/seginternet.git/hooks/post-receive

# Verificar se o hook pode executar systemctl
# O usuário que faz o push é root, então deve funcionar
```

### IP do LXC mudou (DHCP)

Para evitar isso, configure IP fixo editando o container no Proxmox:
```bash
# No host Proxmox
pct set 200 --net0 name=eth0,bridge=vmbr0,ip=192.168.1.200/24,gw=192.168.1.1
pct reboot 200
```

Ou configure uma reserva DHCP no seu roteador pelo MAC address do container.
