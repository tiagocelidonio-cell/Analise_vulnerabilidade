# Guia de instalação — passo a passo (para iniciantes)

Este guia leva você do zero até o sistema rodando, mesmo sem experiência.
São **5 etapas**. Siga na ordem.

> Resumo do que vai acontecer: você instala **um** programa (o Docker), baixa o
> projeto e roda **dois comandos**. O Docker cuida sozinho do banco de dados e
> de todos os serviços — você não instala nada disso manualmente.

---

## Etapa 0 — Qual sistema operacional usar?

Escolha **uma** das opções abaixo. Todas funcionam.

| Opção | Para quem | Recomendado |
|-------|-----------|-------------|
| **Ubuntu 24.04 LTS** (ou 22.04) | Quem quer um servidor/produto estável | ✅ **Sim** |
| **Windows 10/11** | Quem já usa Windows no dia a dia | OK (via Docker Desktop) |
| **macOS** | Quem usa Mac | OK (via Docker Desktop) |

**Recomendação:** se for usar em clientes de verdade, instale numa máquina ou
VM com **Ubuntu 24.04 LTS**. É o caminho mais simples e estável. Pode ser:
- o seu desktop com Ubuntu,
- uma máquina virtual (VirtualBox/VMware),
- ou um servidor na nuvem (AWS EC2, DigitalOcean, Hetzner...).

> ⚠️ **Importante:** este sistema faz varredura de rede. Rode-o numa máquina
> **sua** (ou da sua empresa). Serviços de hospedagem "serverless" (Vercel,
> Netlify, Lovable, etc.) **não** servem para o motor de scan.

---

## Etapa 1 — Baixar o projeto

Você precisa do **Git** (vem junto no script da Etapa 2, no Ubuntu).

Abra o **Terminal** e rode:

```bash
git clone https://github.com/tiagocelidonio-cell/Analise_vulnerabilidade.git
cd Analise_vulnerabilidade
```

> **Windows:** abra o "Terminal" ou o "PowerShell". Se não tiver o Git, baixe em
> https://git-scm.com/download/win e instale com as opções padrão.

Pronto: agora você está **dentro da pasta do projeto**. Todos os comandos
seguintes são rodados aqui.

---

## Etapa 2 — Instalar os pré-requisitos (um script)

Aqui você instala o **Docker** (o único programa necessário).

### No Ubuntu/Debian (recomendado)

Rode o script que instala tudo automaticamente:

```bash
sudo bash install.sh
```

Ele instala Docker + Docker Compose + Git. Ao terminar, aparece a mensagem
`Pronto! Docker instalado`.

> Depois disso, **faça logout e login** (ou reinicie a máquina) uma vez. Isso
> libera o uso do Docker sem `sudo`.

### No Windows ou macOS

O script acima é só para Linux. No Windows/Mac o processo é visual:

1. Baixe o **Docker Desktop**: https://www.docker.com/products/docker-desktop/
2. Instale com as opções padrão (no Windows ele pode pedir para ativar o WSL2 —
   aceite).
3. **Abra o Docker Desktop** e espere o ícone ficar verde ("Engine running").

Pronto. Você já tem os pré-requisitos.

---

## Etapa 3 — Subir o sistema (um script)

Ainda dentro da pasta do projeto, rode:

```bash
bash start.sh
```

O que esse script faz sozinho:
1. Confere se o Docker está rodando.
2. Cria o arquivo de configuração (`.env`) automaticamente.
3. **Pergunta (opcional)** se você tem uma chave da IA (Claude). Se não tiver,
   é só apertar **ENTER** — o sistema funciona mesmo assim, em modo básico.
4. Baixa e sobe **tudo**: banco de dados, fila, armazenamento, API, worker e o
   painel.

> Na **primeira vez** isso demora alguns minutos (ele baixa as imagens). Nas
> próximas é rápido.

Quando terminar, aparece:

```
 VulnScope ESTA NO AR!
   Painel:   http://localhost:5173
   API/docs: http://localhost:8000/docs
   MinIO:    http://localhost:9001
```

---

## Etapa 4 — Acessar e usar

1. Abra o navegador em **http://localhost:5173**
2. Clique em **"+ Novo cliente / engagement"** e preencha:
   - **Cliente** e **Nome do trabalho**
   - **Escopo**: um alvo por linha (ex.: `scanme.nmap.org`, `127.0.0.1`,
     `10.0.0.0/24`)
   - Marque **"Autorizo o scan deste escopo"** (sem isso o scan é bloqueado)
3. Selecione o cliente criado e clique em **"Disparar scan"** (informe os
   alvos).
4. Acompanhe os **achados** aparecerem. Clique num achado para ver detalhes.
5. Use **"Baixar PDF"** para gerar o relatório.

> **Primeiro teste seguro:** use `scanme.nmap.org` — é um alvo público
> disponibilizado justamente para testar scanners.

---

## Etapa 5 — Parar, atualizar e manutenção

| Ação | Comando |
|------|---------|
| **Parar** o sistema (mantém os dados) | `bash stop.sh` |
| **Subir** de novo | `bash start.sh` |
| **Atualizar** para a versão mais nova | `bash update.sh` |
| **Ver o que está acontecendo** (logs) | `docker compose logs -f` |
| **Apagar tudo, inclusive os dados** | `docker compose down -v` |

---

## Solução de problemas (as 4 dúvidas mais comuns)

**"Cannot connect to the Docker daemon" / "Docker nao esta em execucao"**
→ O Docker não está ligado. No Linux: `sudo systemctl start docker`. No
Windows/Mac: abra o Docker Desktop e espere ficar verde.

**"permission denied" ao usar docker (Linux)**
→ Você ainda não relogou depois do `install.sh`. Faça logout/login ou reinicie.
Como alternativa rápida, use `sudo` antes do comando.

**O painel não abre em http://localhost:5173**
→ Espere 1 minuto (na 1ª vez os serviços demoram a iniciar) e recarregue. Para
investigar: `docker compose logs -f web`.

**A porta já está em uso**
→ Outro programa ocupa a porta 5173 ou 8000. Feche-o, ou edite as portas no
arquivo `docker-compose.yml`.

---

## Aviso legal

Use **apenas** em alvos que você tem **autorização por escrito** para testar.
Escanear sistemas de terceiros sem permissão é crime. O campo de autorização no
painel é uma trava técnica — não substitui o contrato com o cliente.
