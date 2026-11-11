# VulnScope

Plataforma de análise de vulnerabilidades assistida por IA, para uso em
múltiplos clientes. Coleta determinística (sem depender de nmap), enriquecimento
com fontes públicas (EPSS/KEV), e uma camada de IA que **raciocina sobre fatos
provados — nunca inventa**.

Roda igual no seu desktop, numa VM on-prem ou na nuvem: tudo containerizado.

## Princípios

1. **Coleta ≠ raciocínio.** Coletores provam fatos (porta aberta, banner).
   A IA só interpreta depois. O LLM nunca "escaneia".
2. **Nada roda sem autorização.** Todo scan exige um `Engagement` autorizado e
   com os alvos dentro do escopo. Gate validado na API **e** no worker.
3. **Evidência é imutável.** Cada achado guarda a prova bruta (banner,
   request/response). Não é regenerada pela IA.
4. **IA é copiloto, não oráculo.** Todo achado carrega confiança + avaliação
   explicável.

## Arquitetura

```
  API (FastAPI) ──enfileira──> Redis ──> Worker (ARQ)
      │                                      │
      │                              Coletores (asyncio)
      ▼                                      │
  PostgreSQL <─────────── Findings + Evidências
      ▲                                      │
      │                          Enriquecimento (EPSS/KEV)
   Painel web                                │
   + Relatórios                      Camada de IA (Claude)
```

## Estrutura

```
backend/app/
  config.py            configuração via ambiente
  db.py                engine/sessão async do SQLAlchemy
  models.py            Engagement, ScanJob, Finding, Evidence
  scope.py             GATE de autorização/escopo
  schemas.py           contratos da API (Pydantic)
  main.py              app FastAPI
  api/                 rotas: engagements, scans, findings
  collectors/          coletores (port_scan asyncio = o "sem nmap")
  enrichment/          EPSS (FIRST) + KEV (CISA)
  ai/                  camada de IA isolada e provider-agnóstica
  worker/              pipeline de scan em background (ARQ)
docker-compose.yml     db + redis + minio + api + worker
```

## Como rodar (um comando)

```bash
cp .env.example .env
docker compose up --build
```

- API:     http://localhost:8000
- Swagger: http://localhost:8000/docs
- MinIO:   http://localhost:9001 (evidências)

> A chave da Claude é opcional. Sem `ANTHROPIC_API_KEY`, a IA cai num modo
> *stub* determinístico e o sistema roda de ponta a ponta mesmo assim.

## Fluxo de uso (via API)

```bash
# 1) cria o engagement do cliente, já autorizado e com escopo
curl -s localhost:8000/engagements -H 'content-type: application/json' -d '{
  "client_name": "ACME", "name": "Externo Q4",
  "scope": ["scanme.nmap.org", "127.0.0.1"],
  "authorized": true, "authorized_by": "voce@empresa.com"
}'

# 2) dispara um scan (so aceita alvos dentro do escopo)
curl -s localhost:8000/engagements/<ID>/scans -H 'content-type: application/json' -d '{
  "targets": ["127.0.0.1"], "ports": [22, 80, 443, 8000]
}'

# 3) acompanha e lê os achados já avaliados pela IA
curl -s localhost:8000/scans/<SCAN_ID>
curl -s localhost:8000/engagements/<ID>/findings
```

## Roadmap (próximos módulos)

- [ ] Coletores web: HTTP fingerprint, TLS, descoberta de subdomínios
- [ ] Correlação banner → CPE → CVE (NVD)
- [ ] Relatório PDF (WeasyPrint) por público (executivo / técnico)
- [ ] Painel React (lista de clientes, achados, evidências, export)
- [ ] Autenticação + multi-usuário
- [ ] Alembic para migrações

## Aviso legal

Ferramenta para testes de segurança **autorizados**. Escanear alvos sem
permissão por escrito é ilegal. O gate de escopo é uma salvaguarda técnica,
não um substituto da autorização contratual do cliente.
