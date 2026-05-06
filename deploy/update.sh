#!/bin/bash
# =============================================================================
# update.sh
# Deploy/atualização do projeto seginternet para o LXC
# Funciona em bash (Linux/macOS/WSL/Git Bash no Windows)
#
# Uso:
#   bash deploy/update.sh <IP_DO_LXC>
#   bash deploy/update.sh 192.168.1.200
#
# Ou defina a variável de ambiente antes de chamar:
#   export LXC_IP=192.168.1.200
#   bash deploy/update.sh
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

info()    { echo -e "${CYAN}[update]${RESET} $*"; }
success() { echo -e "${GREEN}[update] ✓ $*${RESET}"; }
warn()    { echo -e "${YELLOW}[update] ! $*${RESET}"; }
error()   { echo -e "${RED}${BOLD}[update] ✗ ERRO: $*${RESET}"; exit 1; }

# -----------------------------------------------------------------------------
# Obter IP do LXC
# -----------------------------------------------------------------------------
LXC_IP="${1:-$LXC_IP}"

if [[ -z "$LXC_IP" ]]; then
    error "IP do LXC não informado.\nUso: bash deploy/update.sh <IP_DO_LXC>\nOu:  export LXC_IP=<IP>; bash deploy/update.sh"
fi

info "Alvo: root@${LXC_IP}:/opt/seginternet.git"
info "URL final: https://seginternet.rochainf.com.br"
echo ""

# -----------------------------------------------------------------------------
# Verificar se estamos em um repositório git
# -----------------------------------------------------------------------------
if ! git rev-parse --git-dir &>/dev/null; then
    error "Não é um repositório git. Execute 'git init' primeiro."
fi

# -----------------------------------------------------------------------------
# Verificar se o remote 'lxc' está configurado
# -----------------------------------------------------------------------------
REMOTE_URL="ssh://root@${LXC_IP}/opt/seginternet.git"

if ! git remote get-url lxc &>/dev/null; then
    info "Remote 'lxc' não encontrado. Adicionando..."
    git remote add lxc "${REMOTE_URL}"
    success "Remote 'lxc' adicionado: ${REMOTE_URL}"
else
    # Atualizar a URL caso o IP tenha mudado
    CURRENT_URL=$(git remote get-url lxc)
    if [[ "$CURRENT_URL" != "$REMOTE_URL" ]]; then
        warn "URL do remote 'lxc' difere do IP informado."
        warn "  Atual   : ${CURRENT_URL}"
        warn "  Esperada: ${REMOTE_URL}"
        read -r -p "Atualizar a URL? [s/N] " REPLY
        if [[ "${REPLY,,}" == "s" ]]; then
            git remote set-url lxc "${REMOTE_URL}"
            success "URL atualizada."
        fi
    fi
fi

# -----------------------------------------------------------------------------
# Verificar se há mudanças para commitar
# -----------------------------------------------------------------------------
if git diff --quiet && git diff --staged --quiet; then
    # Verificar untracked files
    UNTRACKED=$(git ls-files --others --exclude-standard)
    if [[ -z "$UNTRACKED" ]]; then
        warn "Nenhuma mudança detectada no working tree."
        read -r -p "Fazer push mesmo assim? [s/N] " REPLY
        if [[ "${REPLY,,}" != "s" ]]; then
            info "Operação cancelada."
            exit 0
        fi
    else
        info "Arquivos não rastreados detectados. Adicionando ao commit..."
        git add -A
    fi
else
    # Há mudanças — adicionar tudo e commitar
    info "Detectando mudanças..."
    git add -A
fi

# Commitar se houver algo staged
if ! git diff --staged --quiet; then
    COMMIT_MSG="deploy: $(date '+%Y-%m-%d %H:%M:%S')"
    info "Criando commit: \"${COMMIT_MSG}\""
    git commit -m "${COMMIT_MSG}"
    success "Commit criado."
else
    info "Nada para commitar — apenas fazendo push."
fi

# -----------------------------------------------------------------------------
# Push para o LXC
# -----------------------------------------------------------------------------
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$BRANCH" != "main" ]]; then
    warn "Branch atual é '${BRANCH}', não 'main'."
    warn "O hook post-receive faz checkout de 'main'."
    read -r -p "Continuar mesmo assim (push ${BRANCH}:main)? [s/N] " REPLY
    if [[ "${REPLY,,}" != "s" ]]; then
        info "Operação cancelada. Faça: git checkout main"
        exit 0
    fi
    PUSH_REFSPEC="${BRANCH}:main"
else
    PUSH_REFSPEC="main"
fi

info "Enviando para ssh://root@${LXC_IP}/opt/seginternet.git..."
echo ""
git push lxc "${PUSH_REFSPEC}"
echo ""

# -----------------------------------------------------------------------------
# Resultado final
# -----------------------------------------------------------------------------
success "Push concluído!"
echo ""
echo -e "${GREEN}${BOLD}  https://seginternet.rochainf.com.br${RESET}"
echo ""
