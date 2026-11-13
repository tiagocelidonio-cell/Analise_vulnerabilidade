# Lozinsky VulnScope — Roadmap de Produto

> De **scanner de vulnerabilidades** para **plataforma de Attack Surface Management
> + Pentest** com governança (autorização, NDA, escopo, auditoria).

Este documento é a visão e o plano. Cada onda entrega valor sozinha; marcamos
os itens conforme forem concluídos. Nada aqui quebra o que já existe.

---

## Princípios (não negociáveis)

- **Governança primeiro.** Nenhuma ação ofensiva sem autorização assinada, escopo
  definido e registro em auditoria. NDA e termo por engagement.
- **Operador no comando.** Exploração e escalonamento são *assistidos* (o operador
  confirma), nunca um "worm" autônomo. Sem DoS. Sem movimento lateral automático
  irrestrito.
- **Transparência de marca, não de ferramenta.** A plataforma mostra *capacidades*
  com nomes funcionais ("Descoberta de Portas"), não o binário por trás ("nmap").
  O mapeamento interno existe só para quem mantém o código.
- **Tudo rastreável.** Cada achado tem evidência bruta reproduzível, data/hora,
  alvo e quem rodou. Relatórios no nível profissional (padrão Lozinsky).
- **Escopo é lei.** Todo alvo é validado contra o escopo autorizado antes de
  qualquer toque.

---

## Estado atual (o que já temos)

- Engagements multi-tenant (admin vê todos; consultor só os seus), escopo + flag
  de autorização, sondas intrusivas opt-in.
- Motor de scan em background (fila ARQ) com Parar/Pausar/Retomar e heartbeat.
- Coletores: descoberta de subdomínios (2 fontes), portas/serviços, fingerprint
  web, conteúdo exposto, OSINT (e-mails/domínios/IPs), tecnologias, screenshot,
  vulnerabilidades (templates + CVE por versão de serviço), vazamentos.
- Correlação de CVE (local + NVD), EPSS/KEV, remediação cacheada, **base de CVE
  baixável e monitorada** (NVD paginada).
- Validação SAFE/avançada (não-destrutiva) em background.
- Dashboards customizáveis (drag-and-drop), relatórios PDF/CSV, Administração
  (usuários, integrações/API keys, identidade visual, fuso, base de CVE).

---

## Pilares

1. **Engagements & Governança** — tipos de trabalho, NDA, autorização, VPN, auditoria.
2. **Reconhecimento (OSINT → descoberta recursiva)** — de um domínio a *tudo*.
3. **Superfície de ataque & Tecnologias** — inventário vivo + mapa de tecnologias.
4. **Gestão de Vulnerabilidades** — ciclo de vida, reteste, priorização.
5. **Exploração & Pós-exploração** — assistida, gated, com escalonamento guiado.
6. **Visualização** — topologia do ambiente colorida por risco.
7. **Orquestração** — muitas ferramentas open-source em 2º plano, resultado normalizado.
8. **Relatórios** — executivo + técnico, no padrão dos slides Lozinsky.

---

## Roadmap em ondas

### Onda 0 — Fundamentos de engagement e marca (curto prazo)
- [ ] **Tipos de engagement** (checkbox que habilita capacidades):
  `Análise de Vulnerabilidades`, `Pentest Blackbox`, `Pentest Graybox`,
  `Pentest Whitebox`. O tipo controla o que a ferramenta libera (ex.: exploração
  só em Pentest + autorização).
- [ ] **Upload de documentos do engagement**: NDA e Termo de Autorização (PDF).
  Enquanto não houver autorização válida anexada, ações ofensivas ficam bloqueadas.
- [ ] **Abstração de nomes de ferramentas**: UI passa a mostrar *capacidades*
  (ex.: "Enumeração de Ativos", "Descoberta de Portas", "Verificação de
  Vulnerabilidades"), nunca `nmap/amass/nuclei`. Mapa técnico só no código.
- [ ] **Auditoria**: log imutável de cada ação (quem, o quê, alvo, quando).
- [ ] **Gestão de status do achado**: `aberto → confirmado → em correção →
  corrigido → aceito (risco) → falso-positivo`, com reteste e responsável.

### Onda 1 — Motor de reconhecimento recursivo (ASM)
> O coração da sua visão: de um domínio, descobrir *tudo* e ir aprofundando.
- [ ] **Pipeline de descoberta em grafo**: cada ativo encontrado (domínio →
  subdomínio → IP → porta → serviço → novo host) **re-alimenta a fila**
  automaticamente, com limite de profundidade e escopo.
- [ ] **OSINT abrangente** (inspirado no osintframework): CT logs, DNS/ASN,
  e-mails, buckets, repositórios, metadados — consolidado por empresa.
- [ ] **Superfície de ataque consolidada**: contadores (domínios, subdomínios,
  IPs, serviços) + "o que um atacante vê" (igual aos slides Atvos).
- [ ] **Mapa de tecnologias** por categoria (nuvem, web server, ERP, banco, SO),
  com porta e função — exportável para o relatório.

### Onda 2 — Topologia visual com risco
- [ ] **Grafo do ambiente** (estilo Zenmap, porém web e moderno): nós = hosts/
  domínios/serviços; cor = risco; tamanho = nº de achados; arestas = relação
  (subdomínio→IP, host→porta). Zoom, filtro por severidade, clicar abre o ativo.
- [ ] Exportar a topologia para o relatório (imagem/ً PDF).

### Onda 3 — Acesso à rede do cliente (pentest interno)
- [ ] **VPN por engagement**: upload de config (WireGuard/OpenVPN); os scans
  daquele engagement roteiam pela VPN, isolados por engagement.
- [ ] **Agente/worker interno opcional** (quando VPN não é viável): um coletor
  que o cliente roda na rede dele e devolve resultados com segurança.
- [ ] Descoberta de rede interna (hosts ativos sem ping, segmentos, serviços).

### Onda 4 — Exploração assistida & pós-exploração (gated)
> Só habilita em Pentest + autorização + NDA. Operador confirma cada passo.
- [ ] **Biblioteca de módulos de exploração** (CVEs conhecidos, defaults,
  exposições) — roda contra alvos **no escopo**, com evidência e rollback quando
  aplicável. Nada de exploração em massa automática.
- [ ] **Escalonamento de privilégio guiado**: checagens e provas de conceito
  não-destrutivas, com trilha do caminho ("de X cheguei a Y").
- [ ] **Cadeia de ataque**: registrar o encadeamento (foothold → pivot → alvo)
  para o relatório e a topologia.
- [ ] Trava dura anti-DoS e anti-destruição em todas as camadas.

### Onda 5 — Orquestração robusta (muitas ferramentas em 2º plano)
- [ ] **Framework de módulos plugáveis**: cada ferramenta open-source é um módulo
  com entrada/saída normalizada; a plataforma orquestra dezenas em paralelo,
  deduplica e correlaciona — sempre sob nomes funcionais.
- [ ] **Perfis de varredura** (rápido / completo / furtivo) e **rate-limit/stealth**.
- [ ] Observabilidade: fila, uso de recursos, tempo por módulo.

### Transversal (sempre)
- [ ] **Relatórios profissionais** no padrão Lozinsky: capa, superfície de ataque,
  "o que o atacante vê", tecnologias, riscos por severidade, detalhamento,
  topologia, conclusão. Templates reutilizáveis.
- [ ] Performance e resiliência; testes; documentação de operação.

---

## Decisões em aberto (precisam da sua escolha)

1. **VPN**: WireGuard (simples/rápido) vs OpenVPN (compatível com mais clientes)?
   Sugiro suportar os dois, começando por WireGuard.
2. **Exploração**: confirmo a abordagem *operador-no-loop* (nada autônomo). OK?
3. **Topologia**: biblioteca de grafo (ex.: Cytoscape.js) — leve e poderosa.
4. **Internal agent**: interessa um coletor que o cliente roda na rede dele?

---

## Minha recomendação de sequência

**Agora:** Onda 0 (tipos de engagement + NDA + abstração de nomes + gestão de
achados) — baixo risco, alto valor, destrava o resto.
**Depois:** Onda 1 (recon recursivo + mapa de tecnologias) e Onda 2 (topologia),
que é onde a plataforma vira "profissional" de verdade e gera os slides que você
mostrou. VPN e exploração (Ondas 3–4) vêm quando a base estiver sólida.
