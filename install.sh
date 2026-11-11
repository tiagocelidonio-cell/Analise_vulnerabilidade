#!/usr/bin/env bash
# =====================================================================
#  VulnScope - Instalador de pre-requisitos (Ubuntu/Debian)
#  Instala: Docker + Docker Compose + Git
#  Uso:  sudo bash install.sh
# =====================================================================
set -euo pipefail

echo "=============================================="
echo " VulnScope - instalando pre-requisitos"
echo "=============================================="

# 1) Precisa ser root (sudo)
if [ "$(id -u)" -ne 0 ]; then
  echo "ERRO: rode com sudo. Exemplo:"
  echo "   sudo bash install.sh"
  exit 1
fi

# 2) Este script e para Ubuntu/Debian (apt). Windows/Mac usam Docker Desktop.
if ! command -v apt-get >/dev/null 2>&1; then
  echo "Este script e para Ubuntu/Debian."
  echo "No Windows ou Mac, instale o Docker Desktop (veja INSTALL.md) e pule esta etapa."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# 3) Se o Docker ja estiver instalado, nao refaz
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "Docker ja esta instalado: $(docker --version)"
  echo "Nada a fazer. Pode seguir para:  bash start.sh"
  exit 0
fi

echo "--> Atualizando lista de pacotes..."
apt-get update -y
apt-get install -y ca-certificates curl git

echo "--> Adicionando o repositorio oficial do Docker..."
install -m 0755 -d /etc/apt/keyrings

# Identifica a distro (ubuntu por padrao; debian se for o caso)
# shellcheck disable=SC1091
. /etc/os-release
DOCKER_OS="ubuntu"
[ "${ID:-ubuntu}" = "debian" ] && DOCKER_OS="debian"
CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"

curl -fsSL "https://download.docker.com/linux/${DOCKER_OS}/gpg" -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/${DOCKER_OS} ${CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

echo "--> Instalando Docker e Docker Compose..."
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io \
                   docker-buildx-plugin docker-compose-plugin

echo "--> Habilitando o servico do Docker..."
systemctl enable --now docker

# 4) Permite usar docker sem sudo (aplica apos relogar)
REAL_USER="${SUDO_USER:-}"
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
  usermod -aG docker "$REAL_USER"
  echo "Usuario '$REAL_USER' adicionado ao grupo 'docker'."
  echo "IMPORTANTE: faca logout e login (ou reinicie) para usar docker sem sudo."
fi

echo
echo "=============================================="
echo " Pronto! Docker instalado:"
echo "   $(docker --version)"
echo " Proximo passo:  bash start.sh"
echo "=============================================="
