#!/usr/bin/env bash
# =====================================================================
#  VulnScope - Atualizar para a versao mais nova
#  Uso:  bash update.sh
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"

echo "--> Baixando a versao mais nova do codigo..."
git pull

echo "--> Reconstruindo e reiniciando os servicos..."
docker compose up -d --build

echo "Atualizado! Painel: http://localhost:5173"
