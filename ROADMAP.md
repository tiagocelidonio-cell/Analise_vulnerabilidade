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

## Como as ferramentas funcionam (arquitetura de execução)

### As 4 camadas
```
[Capacidade na UI]  ->  [Módulo]  ->  [Motor: ferramenta/script]  ->  [Normalização]  ->  [Achado]
"Descoberta de Portas"   port_scan     nmap (ou fallback Python)      parser p/ CollectedFact   Finding + Evidência
```
- **Capacidade (UI):** nome funcional, neutro ("Descoberta de Portas"). O usuário
  nunca vê o binário.
- **Módulo:** código Python no worker que sabe montar o comando, rodar e ler a saída.
- **Motor:** a ferramenta open-source consagrada **OU** um script Python próprio
  (fallback). Tudo roda como **processo em segundo plano**, na fila (ARQ), dentro
  do container do worker — com **Parar/Pausar**, heartbeat e validação de escopo.
- **Normalização:** cada saída (XML/JSON/texto) é convertida para um formato único
  (`CollectedFact`) e vira `Finding` com evidência bruta reproduzível.

### "Agente" — 3 significados diferentes (para não confundir)
1. **Agente de IA (Claude):** *analisa*, não ataca. Lê os fatos **já provados**,
   avalia severidade, escreve risco/remediação. Nunca executa exploração. (já existe)
2. **Agente de rede (futuro, Onda 3):** um coletor leve que o **cliente roda na
   rede interna dele** e devolve resultados com segurança — alternativa à VPN.
3. **Agente orquestrador (futuro, Onda 1/5):** o motor que encadeia a descoberta
   (acha um IP → enfileira varredura dele → acha subdomínio → enfileira... ) e
   roda muitos módulos em paralelo. É "automação orquestrada", não IA.

### Scripts, sim — e quais ferramentas (mapa técnico interno)
> Na UI tudo aparece como capacidade. Esta tabela é só para quem mantém o código.

| Capacidade (UI) | Motor principal | Fallback / complemento |
|---|---|---|
| Enumeração de Ativos (subdomínios) | subfinder + amass (passivo) | crt.sh, DNS, wordlist própria |
| Descoberta de Portas/Serviços | nmap (`-sT -sV`) | scanner TCP próprio (Python) |
| Detecção de CVE por versão | nmap `vulners`/`vulscan` | correlação NVD por banner |
| Verificação de Vulnerabilidades web | nuclei (templates) | sondas HTTP próprias |
| Fingerprint / Tecnologias | análise de headers/cookies/HTML (Python) | — |
| Conteúdo exposto | brute de caminhos (Python) | Wayback (archive.org) |
| OSINT (e-mails/domínios/IPs) | site + Google CSE + crt.sh | — |
| Captura de tela | Chromium headless | — |
| Vazamentos | Have I Been Pwned | — |
| Validação SAFE/avançada | sondas HTTP não-destrutivas (Python) | — |

**Futuro (candidatos por onda, a confirmar):**
- **Recon (Onda 1):** dnsx, httpx, asnmap, naabu, theHarvester, feeds de CT.
- **Exploração (Onda 4):** nuclei (templates de exploração), sqlmap, nmap NSE,
  e integração opcional com Metasploit (RPC) — **sempre** disparados pelo operador,
  no escopo, com evidência. Sem automação de exploração em massa.
- **Orquestração (Onda 5):** cada ferramenta vira um "módulo" com entrada/saída
  padronizada; a plataforma agenda dezenas em paralelo, deduplica e correlaciona.

### Princípios de execução
- **Tudo em 2º plano, na fila**, isolado por engagement, com Parar/Pausar e heartbeat.
- **Escopo validado** antes de cada toque; nada fora do autorizado.
- **Killable:** qualquer processo externo é interrompível de verdade (não espera o fim).
- **Resiliente:** se a ferramenta consagrada falta/instabiliza, cai no fallback ou
  registra erro legível (sem derrubar o scan).
- **Evidência bruta** sempre guardada (comando + saída), nunca gerada por IA.

---

## Avaliação de ferramentas candidatas

Critério de encaixe: **roda sem interface (CLI/daemon)**, **automatizável em 2º
plano**, **respeita escopo/autorização**, **sem DoS**, e **cabe numa plataforma
cloud** (ou exige presença na rede do cliente). Legenda: ✅ adota · 🔒 gated
(exploração, só Pentest+autorização) · 🏠 interno (precisa VPN/agente) ·
🖥️ ferramenta de operador (não automatiza; integramos por exportação/conceito) ·
❌ não cabe no cloud.

| Ferramenta | Encaixe | Como entra | Onda |
|---|---|---|---|
| **Nmap** | ✅ (já) | Descoberta de Portas/Serviços | — |
| **theHarvester** | ✅ | OSINT (e-mails, subdomínios, hosts) | 1 |
| **Recon-ng** | ✅ | módulos de OSINT/recon web | 1 |
| **ffuf / Gobuster / Dirb** | ✅ | brute de diretórios/arquivos/subdomínios | 1 |
| **Nikto** | ✅ | checagem de servidor web (misconfig) | 1 |
| **OWASP ZAP** | ✅ | scanner web ativo via daemon/API (headless) | 1/4 |
| **SearchSploit (Exploit-DB)** | ✅ | enriquece achado: "existe exploit?" | 1 |
| **Metasploit Framework** | 🔒 | motor de exploração via RPC (operador dispara) | 4 |
| **SQLmap** | 🔒 | exploração de SQLi, no escopo, modo contido | 4 |
| **Hydra** | 🔒 | brute online — rate-limit forte, risco de lockout | 4 |
| **John the Ripper** | 🔒 | quebra de hash offline (pós-exploração, CPU) | 4 |
| **Hashcat** | 🔒 | quebra via GPU — **exige host com GPU** | 4 |
| **Netcat** | 🔒 | reverse shell / transferência (pós-exploração) | 4 |
| **Responder** | 🏠🔒 | AD interno: LLMNR/NBT-NS → captura NTLM | 3/4 |
| **BloodHound (+SharpHound)** | 🏠🔒 | mapa de caminhos de privilégio no AD | 4 |
| **Mimikatz** | 🏠🔒 | extrai credenciais da memória Windows (pós-ex) | 4 |
| **tshark/Wireshark** | 🏠 | captura de tráfego (interno, via agente) | 3 |
| **Burp Suite** | 🖥️ | ferramenta manual do operador; exportamos alvos | — |
| **Maltego** | 🖥️ | replicamos o valor com nossa **topologia** (grafo) | 2 |
| **BeEF** | 🔒 (nicho) | exploração de navegador; opcional/avançado | 4+ |
| **SET (phishing)** | ⚠️ trilha à parte | engenharia social exige autorização própria por campanha | futuro |
| **Aircrack-ng / Wifite / Kismet** | ❌ no cloud | wireless precisa de **rádio físico** → só via agente on-site com hardware | — |

### Leitura rápida
- **Ganho imediato (Onda 1):** theHarvester, Recon-ng, ffuf/Gobuster, Nikto,
  OWASP ZAP (headless), SearchSploit — é o que tira a sensação de "engine fraca"
  e deixa o recon + web realmente fortes.
- **Exploração (Onda 4, 🔒):** Metasploit (RPC), SQLmap, Hydra, John, Hashcat,
  Netcat — operador dispara, no escopo, com evidência. Nada autônomo.
- **AD/interno (Onda 3–4, 🏠):** Responder, BloodHound, Mimikatz, tshark — exigem
  estar na rede do cliente (VPN ou agente). É o coração do pentest interno.
- **Não cabe no cloud:** wireless (rádio físico). Phishing/SET: trilha separada,
  com autorização própria por campanha.
- **Operador, não módulo:** Burp (manual) e Maltego (cujo valor — grafo de
  relações — a gente entrega com a **topologia** própria).

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
9. **Threat Intelligence & Novidades** — aproveitar a base de CVE como inteligência
   viva: CVEs recentes, exploração ativa (KEV), notícias de ataques e campanhas.

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

### Onda TI — Threat Intelligence & Novidades (aproveitar a base de CVE)
> A base de CVE que baixamos vira **inteligência viva**, não um arquivo parado.
- [ ] **Capturar a data de publicação** dos CVEs no import (campo `published`/
  `lastModified` da NVD) — pré-requisito para ordenar "mais recentes".
- [ ] **Painel "CVEs recentes" na Visão geral** (estilo feed de notícias): últimos
  CVEs baixados/publicados, com severidade, CVSS, se está em KEV (exploração
  ativa) e link. Filtros por severidade/KEV e destaque para os críticos.
- [ ] **"Relevantes para você"**: cruzar os CVEs recentes com as **tecnologias
  detectadas** nos clientes → alertar "saiu um CVE crítico para o Nginx/SAP que
  você tem no cliente X". Esse é o grande diferencial.
- [ ] **Feed de Threat Intelligence**: novidades de segurança (ex.: CISA KEV novos,
  avisos de fornecedores, campanhas/ataques) via fontes públicas/RSS, exibidas
  como notícias. Curado e com data/fonte.
- [ ] **Alertas**: quando um CVE novo em KEV casar com a carteira, notificar
  (painel + opcional e-mail).
- [ ] **Boletim periódico** (opcional): resumo semanal das novidades relevantes
  para a carteira, exportável/encaminhável.

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
