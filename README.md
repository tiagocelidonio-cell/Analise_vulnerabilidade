# VulnScope

Plataforma de análise de vulnerabilidades assistida por IA, para uso em
múltiplos clientes. Coleta determinística (sem depender de nmap), enriquecimento
com fontes públicas (EPSS/KEV), e uma camada de IA que **raciocina sobre fatos
provados — nunca inventa**.

Roda igual no seu desktop, numa VM on-prem ou na nuvem: tudo containerizado.

> 🚀 **É iniciante?** Siga o passo a passo completo em **[INSTALL.md](INSTALL.md)**
> — instala tudo com dois comandos (`install.sh` e `start.sh`).

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
  api/                 rotas: engagements, scans, findings, reports, risk, exploit
  collectors/          port_scan ("sem nmap") + http_probe (web/TLS) +
                       web_content (brute-force de paths) + subdomain_enum
                       (CT/DNS/AXFR) + wayback + google_dorks
  enrichment/          cve_match (banner→CVE/NVD) + EPSS (FIRST) + KEV (CISA)
  ai/                  camada de IA isolada e provider-agnóstica
  risk.py              modelo de risco: probabilidade × impacto → matriz 5×5
  exploitation/        framework de validação SAFE (não-destrutivo, sem DoS)
  reporting/           relatório PDF (WeasyPrint): executivo + técnico
  worker/              pipeline de scan em background (ARQ)
frontend/              painel React (Vite): dashboard de risco, scans, achados
docker-compose.yml     db + redis + minio + api + worker + web
```

## Exploração (validação) — segurança por desenho

A plataforma **comprova** vulnerabilidades, mas de forma não-destrutiva, em
níveis de risco:

| Nível | O que faz | Padrão |
|-------|-----------|--------|
| 🟢 **safe** | Confirma a falha lendo o que está exposto (`.git`, `.env`, listing, backups) | Habilitado |
| 🟡 **intrusive** | Ação ativa sem quebrar nada | Opt-in (interface pronta) |
| 🔴 **DoS / indisponibilidade** | Derrubar o serviço | **Não implementado** |

O motor **recusa** qualquer sonda com risco de disponibilidade. Testes de
indisponibilidade são manuais e exigem autorização separada por escrito. Toda
confirmação vira um achado de confiança 1.0 com a prova anexada (segredos são
mascarados na evidência).

## Como rodar (um comando)

```bash
cp .env.example .env
docker compose up --build
```

- Painel:  http://localhost:5173  ← comece por aqui
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

## Roadmap

- [x] Coletor de portas assíncrono (sem nmap) + banner grab
- [x] Correlação banner → produto/versão → CVE (NVD) com CVSS
- [x] Enriquecimento EPSS (FIRST) + KEV (CISA)
- [x] Coletor web: HTTP fingerprint, TLS, security headers
- [x] Relatório PDF (WeasyPrint): executivo + técnico
- [x] Painel React (clientes, scans, achados, evidências, export)
- [x] Recon: subdomínios (Certificate Transparency + DNS + brute-force + AXFR)
- [x] OSINT: Wayback Machine (arquivos sensíveis históricos) + gerador de Google dorks
- [x] Varredura de diretórios/arquivos web (brute-force de paths)
- [x] Dashboard executivo com matriz de risco (probabilidade × impacto)
- [x] Exploração/validação SAFE não-destrutiva (prova a falha, sem DoS)
- [ ] Autenticação + multi-usuário (RBAC) ← próximo antes de publicar externamente
- [ ] Sondas "intrusive" (opt-in) e relatório incluindo a matriz de risco
- [ ] Alembic para migrações (hoje o schema é criado no boot)
- [ ] Persistência de evidências grandes no S3/MinIO (hoje inline)

## Aviso legal

Ferramenta para testes de segurança **autorizados**. Escanear alvos sem
permissão por escrito é ilegal. O gate de escopo é uma salvaguarda técnica,
não um substituto da autorização contratual do cliente.
