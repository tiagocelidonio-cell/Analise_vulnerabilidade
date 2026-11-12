# Lições aprendidas e checklist de validação (LER ANTES DE MEXER)

Estas regras existem porque cada uma delas custou tempo/tokens para descobrir.
Seguir SEMPRE antes de pedir ao usuário para atualizar na VM dele.

## Validação obrigatória antes de "está pronto"

1. **Backend: importar a app inteira, não só compilar.**
   `python3 -m compileall` NÃO pega erros de registro de rota do FastAPI.
   Validar de verdade com:
   ```bash
   cd backend && python3 -c "import app.main; print(len(app.main.app.routes))"
   ```
   (instalar deps mínimas se faltar: fastapi sqlalchemy[asyncio] asyncpg pydantic
   pydantic-settings arq redis httpx jinja2 pyjwt)

2. **Frontend: `npm run build`** no diretório `frontend/` (já é feito; manter).

3. **Depois de subir, confirmar os dois endpoints:**
   - API viva: `curl -i http://localhost:8000/health` → 200
   - Proxy do painel: `curl -i http://localhost:5173/api/health` → 200

## Armadilhas já corrigidas (não repetir)

- **Rotas `DELETE` com `status_code=204`**: NUNCA usar anotação de retorno
  `-> None` nem response body. Em FastAPI estrito isso derruba a API inteira
  no boot ("Status code 204 must not have a response body").

- **Frontend ↔ API**: o painel fala com a API pelo **proxy `/api`** (mesma
  origem, porta 5173, configurado em `frontend/vite.config.js`). O navegador
  NÃO deve precisar alcançar a porta 8000. `api.js` usa `BASE = VITE_API_URL || "/api"`.

- **`docker-compose.yml` e `${VAR:-default}`**: o `:-` aplica o default quando
  a variável está **vazia OU indefinida**. Por isso `VITE_API_URL` tem default
  **vazio** (`${VITE_API_URL:-}`), senão o painel volta a chamar localhost:8000.

- **Migração de banco**: `Base.metadata.create_all` NÃO altera tabelas que já
  existem. Colunas novas em modelos existentes precisam de
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` em `app/db.py::init_db` (lista `_MIGRATIONS`).

- **"Failed to fetch" no login** = problema de REDE/alcance frontend→API
  (ou API caída), NUNCA senha errada (essa daria "Credenciais inválidas").
  Diagnóstico correto: (1) API viva? (2) proxy /api ok? (3) o que `api.js`
  servido mostra em `VITE_API_URL`? `curl -s localhost:5173/src/api.js | grep VITE_API_URL`.

## Ferramentas externas (motor real)

O scan usa ferramentas consagradas, instaladas no backend/Dockerfile, com
fallback para os coletores Python:
- **nmap** -> `port_scan` (TCP connect `-sT -Pn -sV`, acha host sem ping).
  Roda em LOTES de IPs (port_scan esta em host_collectors, recebe IPs
  expandidos) para que "Parar" e o progresso funcionem no meio de um range.
  `-sV` limitado (`--version-intensity 2 --host-timeout 45s --top-ports 200`).
- **subfinder + amass** -> `subdomain_enum` (duas fontes, deduplicadas, resolve
  A p/ marcar vivos). amass roda em modo PASSIVO (rapido, sem DoS) e e opcional
  (se faltar, segue so com subfinder). Herdado do sistema antigo (tihacks).
- **nmap --script vulners** (perfil COMPLETO) -> acha CVE localmente a partir da
  versao do servico, sem depender de templates/internet do nuclei. Os CVEs caem
  no mesmo pipeline (`fact.data["cve_ids"]`). Perfil basico nao roda scripts.
- **nuclei** -> `web_vuln` (vulns/CVEs; JSONL; precisa de templates/internet).
- nuclei ja traz CVE: o worker usa `fact.data["cve_ids"]` direto quando presente.
- **Google Dorks** (`google_dorks`): com `GOOGLE_CSE_KEY`+`GOOGLE_CSE_CX` EXECUTA
  os dorks pela Programmable Search API (oficial) e traz os achados; sem chave,
  gera o checklist. Nunca raspar o Google (ToS/CAPTCHA).
- **Base local de CVE / remediacao**: tabela `cve_remediation` (cache). Enriquecida
  sob demanda (NVD por CVE, cacheado) e atualizavel: `POST /cve/update` (full=false
  re-busca os CVEs vistos; full=true baixa o bundle oficial CVE List JSON 5.0 de
  `CVE_FEED_URL` e importa tudo). Agenda: `CVE_UPDATE_INTERVAL_HOURS` + cron do ARQ
  (`scheduled_cve_update`). CVE offline tambem via nmap `vulscan` (base CSV local).
- **tech_detect** -> tecnologias (SO/linguagem/framework/CMS/libs/servidor) por
  headers+cookies+HTML. **osint** -> e-mails (site+CSE), dominios (crt.sh), IPs.
  **screenshot** -> captura via Chromium headless (Dockerfile instala chromium);
  a imagem vira Evidence kind="screenshot" (data URI) e renderiza no painel.
  **leaks** -> vazamentos via HIBP (precisa HIBP_API_KEY; sem chave, so explica).
  tech_detect/screenshot sao host_collectors (lote). Registro central do set em
  app/collectors/__init__.py::HOST_COLLECTORS (worker importa de la).
- **status de scan_jobs e VARCHAR** (nao enum nativo): enum nativo do PG quebra
  ao adicionar valores. Valores vem de ScanStatus (str enum).
- **Validacao** (SAFE/avancada) roda como SCAN em background: collectors
  "validate"/"validate_intrusive"; o worker desvia para run_validation.
- Premissas: internet no build (baixa binarios+templates, chromium) e nos scans
  (subfinder/nuclei/osint/leaks). nmap nao precisa de root.

## Contexto do ambiente do usuário

- Roda numa VM (IP ex. 192.168.1.44), acessada de outra máquina pelo navegador.
- Porta 8000 pode estar bloqueada para fora; por isso o proxy `/api` na 5173.
- Repositório é PRIVADO. Atualização na VM: `git pull && docker compose up -d --build`.
- Identidade visual (Lozinsky) em `frontend/src/branding.js`; logo em
  `frontend/public/logo.svg`. Cores: verde #0fdb2b, fundo preto, títulos IBM Plex Mono.

## Regra de ouro

Não terceirizar a validação para o usuário. Reproduzir o boot aqui, confirmar
os dois `curl`, e só então pedir o `git pull`. Cada "tente de novo" sem
validação custa uma rodada inteira.
