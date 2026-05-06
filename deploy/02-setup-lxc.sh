#!/bin/bash
# =============================================================================
# 02-setup-lxc.sh
# Rodar DENTRO DO LXC como root
# Configura o ambiente completo para o projeto seginternet
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# Cores para output
# -----------------------------------------------------------------------------
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RED="\e[31m"
BOLD="\e[1m"
RESET="\e[0m"

info()    { echo -e "\n${CYAN}${BOLD}==> $*${RESET}"; }
success() { echo -e "${GREEN}    ✓ $*${RESET}"; }
warn()    { echo -e "${YELLOW}    ! $*${RESET}"; }
error()   { echo -e "${RED}${BOLD}    ✗ ERRO: $*${RESET}"; exit 1; }

# Verificar se está rodando como root
if [[ "$EUID" -ne 0 ]]; then
    error "Este script deve ser executado como root."
fi

echo -e "\n${GREEN}${BOLD}============================================================"
echo -e "  Setup do LXC — seginternet.rochainf.com.br"
echo -e "============================================================${RESET}\n"

# =============================================================================
# PASSO 1 — Atualizar o sistema
# =============================================================================
info "Atualizando o sistema..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
success "Sistema atualizado."

# =============================================================================
# PASSO 2 — Instalar dependências
# =============================================================================
info "Instalando pacotes necessários..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    openssh-server \
    ufw \
    fail2ban \
    sudo \
    ca-certificates \
    gnupg \
    lsb-release
success "Pacotes instalados."

# =============================================================================
# PASSO 3 — Criar usuário seginternet
# =============================================================================
info "Criando usuário 'seginternet'..."
if id "seginternet" &>/dev/null; then
    warn "Usuário 'seginternet' já existe — pulando criação."
else
    useradd -m -d /home/seginternet -s /bin/bash seginternet
    success "Usuário 'seginternet' criado."
fi

# =============================================================================
# PASSO 4 — Configurar SSH
# =============================================================================
info "Configurando SSH..."

# Habilitar e iniciar o SSH
systemctl enable ssh --quiet
systemctl start ssh

# Criar diretório .ssh para o usuário seginternet
mkdir -p /home/seginternet/.ssh
touch /home/seginternet/.ssh/authorized_keys
chmod 700 /home/seginternet/.ssh
chmod 600 /home/seginternet/.ssh/authorized_keys
chown -R seginternet:seginternet /home/seginternet/.ssh

# Criar diretório .ssh para root também
mkdir -p /root/.ssh
touch /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# Reforçar configurações de segurança do SSH
cat > /etc/ssh/sshd_config.d/99-seginternet.conf << 'EOF'
# Configurações de segurança para o servidor seginternet
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
X11Forwarding no
PrintMotd no
EOF

systemctl restart ssh
success "SSH configurado."
warn "ATENÇÃO: Adicione sua chave pública em /root/.ssh/authorized_keys e em"
warn "         /home/seginternet/.ssh/authorized_keys antes de desabilitar o acesso por senha!"
warn "         Use o script deploy/add-ssh-key.sh para isso."

# =============================================================================
# PASSO 5 — Configurar UFW (firewall)
# =============================================================================
info "Configurando firewall (UFW)..."

# Resetar regras existentes
ufw --force reset > /dev/null 2>&1

# Políticas padrão
ufw default deny incoming
ufw default allow outgoing

# Regras permitidas
ufw allow 22/tcp comment 'SSH'
ufw allow 8501/tcp comment 'Streamlit (acesso interno)'

# Habilitar UFW
ufw --force enable

success "UFW configurado e habilitado."
ufw status numbered

# =============================================================================
# PASSO 6 — Configurar fail2ban
# =============================================================================
info "Configurando fail2ban..."
systemctl enable fail2ban --quiet
systemctl start fail2ban
success "fail2ban ativo."

# =============================================================================
# PASSO 7 — Criar diretório do projeto
# =============================================================================
info "Criando diretório do projeto /opt/seginternet..."
mkdir -p /opt/seginternet
chown seginternet:seginternet /opt/seginternet
chmod 755 /opt/seginternet
success "Diretório /opt/seginternet criado."

# =============================================================================
# PASSO 8 — Criar git bare repository com hook post-receive
# =============================================================================
info "Criando git bare repository em /opt/seginternet.git..."

git init --bare /opt/seginternet.git
chown -R root:root /opt/seginternet.git

# Criar o hook post-receive
cat > /opt/seginternet.git/hooks/post-receive << 'HOOK'
#!/bin/bash
# Hook post-receive — executado após git push
# Deploy automático do projeto seginternet

GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RED="\e[31m"
RESET="\e[0m"

echo -e "\n${CYAN}[deploy] Iniciando deploy de seginternet...${RESET}"

# Forçar checkout do branch main no diretório de trabalho
GIT_WORK_TREE=/opt/seginternet GIT_DIR=/opt/seginternet.git git checkout -f main

# Entrar no diretório do projeto
cd /opt/seginternet

# Garantir permissões corretas
chown -R seginternet:seginternet /opt/seginternet

# Instalar/atualizar dependências Python
echo -e "${CYAN}[deploy] Instalando dependências Python...${RESET}"
if [[ -f requirements.txt ]]; then
    /opt/seginternet/.venv/bin/pip install -r requirements.txt -q
    echo -e "${GREEN}[deploy] Dependências instaladas.${RESET}"
else
    echo -e "${YELLOW}[deploy] requirements.txt não encontrado — pulando pip install.${RESET}"
fi

# Reiniciar o serviço
echo -e "${CYAN}[deploy] Reiniciando serviço seginternet...${RESET}"
systemctl restart seginternet

# Aguardar o serviço subir
sleep 2
if systemctl is-active --quiet seginternet; then
    echo -e "\n${GREEN}✓ Deploy concluido — seginternet.rochainf.com.br atualizado${RESET}\n"
else
    echo -e "\n${RED}✗ ATENÇÃO: serviço seginternet não subiu! Verifique com: journalctl -u seginternet -n 50${RESET}\n"
    exit 1
fi
HOOK

chmod +x /opt/seginternet.git/hooks/post-receive
success "Git bare repo criado em /opt/seginternet.git"
success "Hook post-receive configurado."

# =============================================================================
# PASSO 9 — Criar virtualenv Python
# =============================================================================
info "Criando virtualenv Python em /opt/seginternet/.venv..."
python3 -m venv /opt/seginternet/.venv
chown -R seginternet:seginternet /opt/seginternet/.venv
success "Virtualenv criado."

# Instalar pip atualizado e wheel no venv
/opt/seginternet/.venv/bin/pip install --upgrade pip wheel --quiet
success "pip e wheel atualizados no venv."

# =============================================================================
# PASSO 10 — Instalar cloudflared
# =============================================================================
info "Instalando cloudflared..."

# Detectar arquitetura
ARCH=$(dpkg --print-architecture)
if [[ "$ARCH" == "amd64" ]]; then
    CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"
elif [[ "$ARCH" == "arm64" ]]; then
    CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb"
else
    error "Arquitetura não suportada: ${ARCH}. Instale o cloudflared manualmente."
fi

TMP_DEB="/tmp/cloudflared.deb"
curl -fsSL "${CF_URL}" -o "${TMP_DEB}"
dpkg -i "${TMP_DEB}"
rm -f "${TMP_DEB}"

# Verificar instalação
if ! command -v cloudflared &>/dev/null; then
    error "cloudflared não foi instalado corretamente."
fi

CF_VERSION=$(cloudflared --version 2>&1 | head -1)
success "cloudflared instalado: ${CF_VERSION}"

# Criar diretório de configuração do cloudflared
mkdir -p /etc/cloudflared
mkdir -p /root/.cloudflared

# =============================================================================
# PASSO 11 — Instalar systemd services
# =============================================================================
info "Instalando serviços systemd..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- seginternet.service ---
if [[ -f "${SCRIPT_DIR}/seginternet.service" ]]; then
    cp "${SCRIPT_DIR}/seginternet.service" /etc/systemd/system/seginternet.service
    success "seginternet.service copiado."
else
    warn "seginternet.service não encontrado em ${SCRIPT_DIR}. Criando a partir do template..."
    cat > /etc/systemd/system/seginternet.service << 'EOF'
[Unit]
Description=Seginternet — Streamlit App
After=network.target
Wants=network.target

[Service]
Type=simple
User=seginternet
WorkingDirectory=/opt/seginternet
Environment="PYTHONUNBUFFERED=1"
ExecStart=/opt/seginternet/.venv/bin/python -m streamlit run app.py \
    --server.port 8501 \
    --server.headless true \
    --server.address 127.0.0.1
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=seginternet

[Install]
WantedBy=multi-user.target
EOF
    success "seginternet.service criado a partir do template."
fi

# --- cloudflared.service ---
if [[ -f "${SCRIPT_DIR}/cloudflared.service" ]]; then
    cp "${SCRIPT_DIR}/cloudflared.service" /etc/systemd/system/cloudflared.service
    success "cloudflared.service copiado."
else
    warn "cloudflared.service não encontrado em ${SCRIPT_DIR}. Criando a partir do template..."
    cat > /etc/systemd/system/cloudflared.service << 'EOF'
[Unit]
Description=Cloudflare Tunnel — seginternet
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/cloudflared tunnel --config /etc/cloudflared/config.yml run
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cloudflared

[Install]
WantedBy=multi-user.target
EOF
    success "cloudflared.service criado a partir do template."
fi

# --- Copiar config do cloudflared se existir ---
if [[ -f "${SCRIPT_DIR}/cloudflared-config.yml" ]]; then
    cp "${SCRIPT_DIR}/cloudflared-config.yml" /etc/cloudflared/config.yml
    success "cloudflared-config.yml copiado para /etc/cloudflared/config.yml"
fi

# Recarregar systemd e habilitar serviços
systemctl daemon-reload
systemctl enable seginternet
systemctl enable cloudflared

success "Serviços habilitados no systemd."
warn "seginternet não será iniciado agora (aguardando primeiro deploy via git push)."
warn "cloudflared não será iniciado agora (aguardando configuração do tunnel)."

# =============================================================================
# INSTRUÇÕES FINAIS
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}============================================================"
echo -e "  Setup concluido! Próximos passos:"
echo -e "============================================================${RESET}"
echo ""
echo -e "${YELLOW}${BOLD}1. Adicionar chave SSH (na sua máquina local):${RESET}"
echo -e "   ${CYAN}bash deploy/add-ssh-key.sh \$(hostname -I | awk '{print \$1}')${RESET}"
echo ""
echo -e "${YELLOW}${BOLD}2. Configurar o Cloudflare Tunnel:${RESET}"
echo -e "   ${CYAN}cloudflared tunnel login${RESET}"
echo -e "   ${CYAN}cloudflared tunnel create seginternet${RESET}"
echo -e "   # Copie o Tunnel ID exibido e edite:"
echo -e "   ${CYAN}nano /etc/cloudflared/config.yml${RESET}"
echo -e "   # Substitua TUNNEL_ID_AQUI pelo ID real"
echo -e "   ${CYAN}cloudflared tunnel route dns seginternet seginternet.rochainf.com.br${RESET}"
echo -e "   ${CYAN}systemctl start cloudflared${RESET}"
echo ""
echo -e "${YELLOW}${BOLD}3. Fazer o primeiro deploy (na sua máquina local):${RESET}"
echo -e "   ${CYAN}git remote add lxc ssh://root@\$(hostname -I | awk '{print \$1}')/opt/seginternet.git${RESET}"
echo -e "   ${CYAN}git push lxc main${RESET}"
echo ""
echo -e "${YELLOW}${BOLD}4. Verificar:${RESET}"
echo -e "   ${CYAN}systemctl status seginternet${RESET}"
echo -e "   ${CYAN}systemctl status cloudflared${RESET}"
echo -e "   ${CYAN}curl -s http://localhost:8501/healthz${RESET}"
echo ""
echo -e "${GREEN}IP deste container: $(hostname -I | awk '{print $1}')${RESET}"
echo -e "${GREEN}============================================================${RESET}"
