"""Google dorking REAL via Google Programmable Search API (dentro do ToS).

Com GOOGLE_CSE_KEY + GOOGLE_CSE_CX configurados, executa cada dork pela API
oficial e retorna os RESULTADOS ENCONTRADOS (URLs reais expostas) como achados.
Sem chave, cai no modo checklist (gera as buscas prontas para o analista).

Nao raspa o Google (isso viola o ToS e e bloqueado). A API oficial tem cota
gratuita (100 consultas/dia); crie em:
  - CX:  https://programmablesearchengine.google.com  (marque "buscar toda a web")
  - KEY: https://developers.google.com/custom-search/v1/overview
"""
from __future__ import annotations

import asyncio
from urllib.parse import quote_plus

import httpx

from app.collectors.base import CollectedFact
from app.config import settings

CSE_URL = "https://www.googleapis.com/customsearch/v1"

# (categoria, consulta com {d} = dominio, severidade do que for ENCONTRADO)
_DORKS: list[tuple[str, str, str]] = [
    ("Documentos publicos expostos",
     "site:{d} ext:doc | ext:docx | ext:odt | ext:rtf | ext:ppt | ext:pptx | ext:csv", "low"),
    ("Directory listing (index of)",
     "site:{d} intitle:index.of", "medium"),
    ("Arquivos de configuracao",
     "site:{d} ext:xml | ext:conf | ext:cnf | ext:cfg | ext:ini | ext:env | ext:yml | ext:json", "high"),
    ("Arquivos de banco de dados",
     "site:{d} ext:sql | ext:dbf | ext:mdb", "high"),
    ("Arquivos de log",
     "site:{d} ext:log", "medium"),
    ("Backups e arquivos antigos",
     "site:{d} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup", "high"),
    ("Paginas de login",
     'site:{d} inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth', "info"),
    ("Erros de SQL",
     'site:{d} intext:"sql syntax near" | intext:"syntax error has occurred" | '
     'intext:"incorrect syntax near" | intext:"Warning: mysql_connect()"', "high"),
    ("Erros/avisos de PHP",
     'site:{d} "PHP Parse error" | "PHP Warning" | "PHP Error"', "medium"),
    ("phpinfo()",
     'site:{d} ext:php intitle:phpinfo "published by the PHP Group"', "high"),
    ("Vazamentos em sites de paste",
     'site:pastebin.com | site:justpaste.it | site:hastebin.com | '
     'site:controlc.com | site:ghostbin.com "{d}"', "high"),
    ("Exposicao em GitHub/GitLab",
     'site:github.com | site:gitlab.com "{d}"', "medium"),
    ("Paginas de cadastro",
     "site:{d} inurl:signup | inurl:register | intitle:Signup", "info"),
]


class GoogleDorksCollector:
    name = "google_dorks"

    async def run(self, targets: list[str], **kwargs) -> list[CollectedFact]:
        if settings.google_cse_enabled:
            return await self._run_real(targets, kwargs.get("cancel_check"))
        return self._run_checklist(targets)

    # --- Modo REAL: executa via API oficial e devolve o que foi encontrado ---
    async def _run_real(self, targets: list[str], cancel_check=None) -> list[CollectedFact]:
        facts: list[CollectedFact] = []
        async with httpx.AsyncClient(timeout=20) as client:
            for domain in targets:
                for category, template, sev in _DORKS:
                    if cancel_check and await cancel_check():
                        return facts
                    query = template.format(d=domain)
                    items = await self._search(client, query)
                    if not items:
                        continue
                    for it in items:
                        link = it.get("link", "")
                        snippet = (it.get("snippet", "") or "").replace("\n", " ")
                        facts.append(CollectedFact(
                            target=domain, service="osint",
                            title=f"[Dork: {category}] {link[:90]}",
                            raw=f"{link}\n{snippet}\n\nDork: {query}",
                            data={"severity_hint": sev, "category": category,
                                  "query": query, "link": link,
                                  "source": "google_cse"},
                        ))
        return facts

    async def _search(self, client: httpx.AsyncClient, query: str) -> list[dict]:
        params = {
            "key": settings.google_cse_key, "cx": settings.google_cse_cx,
            "q": query, "num": min(settings.google_cse_max_per_dork, 10),
        }
        for attempt in range(2):
            try:
                resp = await client.get(CSE_URL, params=params)
                if resp.status_code == 429:  # cota/rate limit
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                if resp.status_code >= 400:
                    return []
                return resp.json().get("items", []) or []
            except (httpx.HTTPError, ValueError):
                return []
        return []

    # --- Modo checklist (sem chave): gera as buscas prontas p/ o analista ---
    def _run_checklist(self, targets: list[str]) -> list[CollectedFact]:
        facts: list[CollectedFact] = []
        for domain in targets:
            for category, template, _sev in _DORKS:
                query = template.format(d=domain)
                link = "https://www.google.com/search?q=" + quote_plus(query)
                facts.append(CollectedFact(
                    target=domain, service="osint",
                    title=f"[Dork] {category}",
                    raw=f"{query}\n\nExecutar: {link}",
                    data={"severity_hint": "info", "category": category,
                          "query": query, "link": link, "source": "google_dork",
                          "note": "Configure GOOGLE_CSE_KEY/CX para busca automatica"},
                ))
        return facts
