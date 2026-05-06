#!/bin/bash
# =============================================================================
# 01-proxmox-create-lxc.sh
# Rodar NO HOST PROXMOX (via SSH ou diretamente no shell do Proxmox)
# Cria o container LXC para o projeto seginternet
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES — ajuste conforme necessário
# -----------------------------------------------------------------------------
CT_ID=200                          # ID do container (deve ser único no Proxmox)
HOSTNAME="seginternet"
TEMPLATE="local:vztmpl/ubuntu-24.04-standard_24.04-2_amd64.tar.zst"
STORAGE="local-lvm"                # Storage para o rootfs do container
BRIDGE="vmbr0"                     # Bridge de rede (padrão Proxmox)
CORES=2                            # Número de vCPUs
MEMORY=1024                        # RAM em MB
DISK=8                             # Disco em GB
PASSWORD="changeme123"             # Senha root temporária — TROQUE APÓS O SETUP!

# Rede — por padrão usa DHCP
# Para IP fixo, substitua a linha NET abaixo por:
#   NET="name=eth0,bridge=${BRIDGE},ip=192.168.1.200/24,gw=192.168.1.1"
NET="name=eth0,bridge=${BRIDGE},ip=dhcp"

# -----------------------------------------------------------------------------
# Cores para output
# -----------------------------------------------------------------------------
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RED="\e[31m"
RESET="\e[0m"

info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERR]${RESET}  $*"; exit 1; }

# -----------------------------------------------------------------------------
# Verificações
# -----------------------------------------------------------------------------
info "Verificando se o CT ID ${CT_ID} já existe..."
if pct status "${CT_ID}" &>/dev/null; then
    error "Container ${CT_ID} já existe. Escolha outro CT_ID ou remova-o primeiro."
fi

info "Verificando se o template existe em local:vztmpl..."
if ! pveam list local | grep -q "ubuntu-24.04-standard_24.04-2_amd64"; then
    warn "Template não encontrado localmente. Baixando..."
    pveam download local ubuntu-24.04-standard_24.04-2_amd64.tar.zst || \
        error "Falha ao baixar o template. Execute manualmente: pveam download local ubuntu-24.04-standard_24.04-2_amd64.tar.zst"
fi

# -----------------------------------------------------------------------------
# Criar o container
# -----------------------------------------------------------------------------
info "Criando container LXC ${CT_ID} (${HOSTNAME})..."

pct create "${CT_ID}" "${TEMPLATE}" \
    --hostname "${HOSTNAME}" \
    --storage "${STORAGE}" \
    --rootfs "${STORAGE}:${DISK}" \
    --cores "${CORES}" \
    --memory "${MEMORY}" \
    --swap 512 \
    --net0 "${NET}" \
    --password "${PASSWORD}" \
    --unprivileged 1 \
    --features nesting=1 \
    --ostype ubuntu \
    --start 0

success "Container ${CT_ID} criado com sucesso."

# -----------------------------------------------------------------------------
# Ajustes pós-criação
# -----------------------------------------------------------------------------
info "Configurando opções adicionais..."

# Habilita keyctl (necessário para alguns recursos no Ubuntu 24.04 em LXC)
pct set "${CT_ID}" --features nesting=1,keyctl=1

success "Opções configuradas."

# -----------------------------------------------------------------------------
# Iniciar o container
# -----------------------------------------------------------------------------
info "Iniciando container ${CT_ID}..."
pct start "${CT_ID}"

# Aguarda o container iniciar e obter IP via DHCP
info "Aguardando o container inicializar e obter IP DHCP (30s)..."
sleep 30

# -----------------------------------------------------------------------------
# Exibir informações finais
# -----------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================================${RESET}"
echo -e "${GREEN}  Container ${CT_ID} (${HOSTNAME}) criado e iniciado!${RESET}"
echo -e "${GREEN}============================================================${RESET}"

# Tentar obter o IP via pct exec
CT_IP=$(pct exec "${CT_ID}" -- hostname -I 2>/dev/null | awk '{print $1}' || echo "não disponível ainda")
echo ""
echo -e "  IP do container : ${YELLOW}${CT_IP}${RESET}"
echo -e "  Hostname        : ${HOSTNAME}"
echo -e "  CT ID           : ${CT_ID}"
echo -e "  Senha root      : ${YELLOW}${PASSWORD}${RESET} (troque após o setup!)"
echo ""
echo -e "  Próximo passo — copie o script de setup para o container e execute:"
echo -e "  ${CYAN}scp deploy/02-setup-lxc.sh root@${CT_IP}:/root/${RESET}"
echo -e "  ${CYAN}ssh root@${CT_IP} 'bash /root/02-setup-lxc.sh'${RESET}"
echo ""
echo -e "  Ou acesse diretamente pelo Proxmox:"
echo -e "  ${CYAN}pct enter ${CT_ID}${RESET}"
echo -e "${GREEN}============================================================${RESET}"
