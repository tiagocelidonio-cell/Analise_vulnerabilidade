#!/usr/bin/env bash
# =====================================================================
#  VulnScope - Subir o sistema (bancos + API + worker + painel)
#  Uso:  bash start.sh
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"

echo "=============================================="
echo " VulnScope - subindo o sistema"
echo "=============================================="

# 1) Docker instalado?
if ! command -v docker >/dev/null 2>&1; then
  echo "ERRO: Docker nao encontrado."
  echo "Rode primeiro:  sudo bash install.sh"
  echo "(No Windows/Mac, abra o Docker Desktop antes de continuar.)"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERRO: plugin 'docker compose' nao encontrado. Reinstale o Docker (install.sh)."
  exit 1
fi

# 2) Docker esta rodando?
if ! docker info >/dev/null 2>&1; then
  echo "ERRO: o Docker nao esta em execucao."
  echo " - Linux:  sudo systemctl start docker"
  echo " - Win/Mac: abra o aplicativo Docker Desktop e aguarde ficar verde."
  exit 1
fi

# 3) Cria o arquivo de configuracao .env se nao existir
if [ ! -f .env ]; then
  cp .env.example .env
  echo "--> Arquivo de configuracao '.env' criado."
fi

# 4) (Opcional) pergunta a chave da IA, so se o terminal for interativo
if [ -t 0 ] && ! grep -qE '^ANTHROPIC_API_KEY=.+' .env; then
  echo
  echo "Chave da IA (Claude) - OPCIONAL."
  echo "Sem ela o sistema funciona em modo basico; com ela a analise fica melhor."
  printf "Cole a ANTHROPIC_API_KEY (ou apenas aperte ENTER para pular): "
  read -r KEY || true
  if [ -n "${KEY:-}" ]; then
    if grep -q '^ANTHROPIC_API_KEY=' .env; then
      sed -i.bak "s|^ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${KEY}|" .env && rm -f .env.bak
    else
      echo "ANTHROPIC_API_KEY=${KEY}" >> .env
    fi
    echo "--> Chave salva."
  fi
fi

# 5) Constroi e sobe tudo em segundo plano
echo
echo "--> Construindo e subindo os servicos..."
echo "    (na 1a vez isso baixa imagens e pode levar alguns minutos)"
docker compose up -d --build

# 6) Espera a API responder
echo
echo "--> Aguardando a API ficar pronta..."
READY=0
for _ in $(seq 1 60); do
  if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 3
done

echo
echo "=============================================="
if [ "$READY" -eq 1 ]; then
  echo " VulnScope ESTA NO AR!"
else
  echo " Servicos subindo (a API ainda esta inicializando)."
  echo " Aguarde 1 minuto e recarregue o painel."
fi
echo
echo "   Painel:   http://localhost:5173    <- comece aqui"
echo "   API/docs: http://localhost:8000/docs"
echo "   MinIO:    http://localhost:9001    (login: minioadmin / minioadmin)"
echo
echo " Para ver os logs:  docker compose logs -f"
echo " Para parar:        bash stop.sh"
echo "=============================================="
