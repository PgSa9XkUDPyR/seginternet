#!/bin/bash
# =============================================================================
# add-ssh-key.sh
# Copia a chave SSH pública local para o LXC (root e seginternet)
# Rodar na máquina local (Linux, macOS, WSL ou Git Bash no Windows)
#
# Uso:
#   bash deploy/add-ssh-key.sh <IP_DO_LXC>
#   bash deploy/add-ssh-key.sh 192.168.1.200
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# Cores
# -----------------------------------------------------------------------------
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RED="\e[31m"
BOLD="\e[1m"
RESET="\e[0m"

info()    { echo -e "${CYAN}[ssh-key]${RESET} $*"; }
success() { echo -e "${GREEN}[ssh-key] ✓ $*${RESET}"; }
warn()    { echo -e "${YELLOW}[ssh-key] ! $*${RESET}"; }
error()   { echo -e "${RED}${BOLD}[ssh-key] ✗ ERRO: $*${RESET}"; exit 1; }

# -----------------------------------------------------------------------------
# Verificar argumentos
# -----------------------------------------------------------------------------
LXC_IP="${1:-$LXC_IP}"

if [[ -z "$LXC_IP" ]]; then
    error "IP do LXC não informado.\nUso: bash deploy/add-ssh-key.sh <IP_DO_LXC>"
fi

# -----------------------------------------------------------------------------
# Encontrar a chave pública
# -----------------------------------------------------------------------------
PUBKEY_FILE=""

# Ordem de preferência: ed25519, rsa, ecdsa
for KEY_TYPE in id_ed25519 id_rsa id_ecdsa; do
    CANDIDATE="${HOME}/.ssh/${KEY_TYPE}.pub"
    if [[ -f "$CANDIDATE" ]]; then
        PUBKEY_FILE="$CANDIDATE"
        break
    fi
done

# Suporte a caminhos Windows (via WSL ou Git Bash)
if [[ -z "$PUBKEY_FILE" ]] && command -v wslpath &>/dev/null; then
    WIN_HOME=$(wslpath "$(cmd.exe /c "echo %USERPROFILE%" 2>/dev/null | tr -d '\r')")
    for KEY_TYPE in id_ed25519 id_rsa id_ecdsa; do
        CANDIDATE="${WIN_HOME}/.ssh/${KEY_TYPE}.pub"
        if [[ -f "$CANDIDATE" ]]; then
            PUBKEY_FILE="$CANDIDATE"
            break
        fi
    done
fi

if [[ -z "$PUBKEY_FILE" ]]; then
    error "Nenhuma chave SSH pública encontrada em ~/.ssh/\n" \
          "Gere uma com: ssh-keygen -t ed25519 -C \"seu@email.com\""
fi

PUBKEY_CONTENT=$(cat "$PUBKEY_FILE")
info "Chave encontrada: ${PUBKEY_FILE}"
info "Chave pública: ${PUBKEY_CONTENT:0:50}..."

# -----------------------------------------------------------------------------
# Verificar conectividade (senha ainda habilitada ou acesso direto)
# -----------------------------------------------------------------------------
info "Conectando ao LXC ${LXC_IP}..."
echo ""
warn "Será solicitada a senha root do LXC (definida em 01-proxmox-create-lxc.sh)."
warn "Após adicionar a chave, o login por senha será desabilitado."
echo ""

# -----------------------------------------------------------------------------
# Copiar chave para root
# -----------------------------------------------------------------------------
info "Adicionando chave para root@${LXC_IP}..."
ssh -o StrictHostKeyChecking=accept-new \
    -o PasswordAuthentication=yes \
    "root@${LXC_IP}" \
    "mkdir -p /root/.ssh && \
     chmod 700 /root/.ssh && \
     echo '${PUBKEY_CONTENT}' >> /root/.ssh/authorized_keys && \
     chmod 600 /root/.ssh/authorized_keys && \
     # Remover duplicatas
     sort -u /root/.ssh/authorized_keys > /tmp/ak_tmp && mv /tmp/ak_tmp /root/.ssh/authorized_keys && \
     echo 'Chave adicionada para root.'"

success "Chave adicionada para root@${LXC_IP}"

# -----------------------------------------------------------------------------
# Copiar chave para seginternet
# -----------------------------------------------------------------------------
info "Adicionando chave para seginternet@${LXC_IP}..."
ssh -o StrictHostKeyChecking=accept-new \
    "root@${LXC_IP}" \
    "mkdir -p /home/seginternet/.ssh && \
     chmod 700 /home/seginternet/.ssh && \
     echo '${PUBKEY_CONTENT}' >> /home/seginternet/.ssh/authorized_keys && \
     chmod 600 /home/seginternet/.ssh/authorized_keys && \
     chown -R seginternet:seginternet /home/seginternet/.ssh && \
     sort -u /home/seginternet/.ssh/authorized_keys > /tmp/ak_tmp && \
     mv /tmp/ak_tmp /home/seginternet/.ssh/authorized_keys && \
     echo 'Chave adicionada para seginternet.'"

success "Chave adicionada para seginternet@${LXC_IP}"

# -----------------------------------------------------------------------------
# Testar acesso por chave
# -----------------------------------------------------------------------------
info "Testando acesso por chave SSH..."
if ssh -o BatchMode=yes \
       -o ConnectTimeout=5 \
       -o StrictHostKeyChecking=no \
       "root@${LXC_IP}" "echo ok" &>/dev/null; then
    success "Acesso por chave funcionando para root@${LXC_IP}!"
else
    warn "Não foi possível confirmar o acesso por chave. Verifique manualmente:"
    warn "  ssh root@${LXC_IP}"
fi

echo ""
echo -e "${GREEN}${BOLD}============================================================${RESET}"
echo -e "${GREEN}  Chave SSH configurada com sucesso!${RESET}"
echo -e "${GREEN}============================================================${RESET}"
echo ""
echo -e "  Acesso root    : ${CYAN}ssh root@${LXC_IP}${RESET}"
echo -e "  Acesso usuário : ${CYAN}ssh seginternet@${LXC_IP}${RESET}"
echo ""
