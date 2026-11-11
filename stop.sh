#!/usr/bin/env bash
# =====================================================================
#  VulnScope - Parar o sistema
#  Uso:  bash stop.sh
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"

docker compose down

echo
echo "VulnScope parado. Seus dados (banco e evidencias) foram PRESERVADOS."
echo "Para subir de novo:  bash start.sh"
echo
echo "Para apagar TUDO, inclusive os dados (acao irreversivel):"
echo "   docker compose down -v"
