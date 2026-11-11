"""Gerador de Google dorks — assistente de OSINT para o analista.

NAO raspa o Google (viola o ToS e e bloqueado por CAPTCHA). Em vez disso,
gera as consultas prontas e o link clicavel para o analista executar e
revisar manualmente. A busca automatizada do mesmo tipo de exposicao e
feita pelo coletor Wayback (fonte com API legitima).

Cada dork vira um CollectedFact de severidade 'info' (uma pista a investigar,
nao uma vulnerabilidade confirmada) e aparece como checklist no relatorio.
"""
from __future__ import annotations

from urllib.parse import quote_plus

from app.collectors.base import CollectedFact

# (categoria, consulta com {d} = dominio)
_DORKS: list[tuple[str, str]] = [
    ("Documentos publicos expostos",
     "site:{d} ext:doc | ext:docx | ext:odt | ext:rtf | ext:ppt | ext:pptx | ext:csv"),
    ("Directory listing (index of)",
     "site:{d} intitle:index.of"),
    ("Arquivos de configuracao",
     "site:{d} ext:xml | ext:conf | ext:cnf | ext:cfg | ext:ini | ext:env | ext:yml | ext:json"),
    ("Arquivos de banco de dados",
     "site:{d} ext:sql | ext:dbf | ext:mdb"),
    ("Arquivos de log",
     "site:{d} ext:log"),
    ("Backups e arquivos antigos",
     "site:{d} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup"),
    ("Paginas de login",
     'site:{d} inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth'),
    ("Subdominios",
     "site:*.{d}"),
    ("Sub-subdominios",
     "site:*.*.{d}"),
    ("Erros de SQL",
     'site:{d} intext:"sql syntax near" | intext:"syntax error has occurred" | '
     'intext:"incorrect syntax near" | intext:"Warning: mysql_connect()"'),
    ("Erros/avisos de PHP",
     'site:{d} "PHP Parse error" | "PHP Warning" | "PHP Error"'),
    ("phpinfo()",
     'site:{d} ext:php intitle:phpinfo "published by the PHP Group"'),
    ("Vazamentos em sites de paste",
     'site:pastebin.com | site:justpaste.it | site:hastebin.com | '
     'site:controlc.com | site:ghostbin.com "{d}"'),
    ("Exposicao em GitHub/GitLab",
     'site:github.com | site:gitlab.com "{d}"'),
    ("Mencoes no Stack Overflow",
     'site:stackoverflow.com "{d}"'),
    ("Paginas de cadastro",
     "site:{d} inurl:signup | inurl:register | intitle:Signup"),
    ("Historico no Wayback Machine",
     "https://web.archive.org/web/*/{d}/*"),
]


class GoogleDorksCollector:
    name = "google_dorks"

    async def run(self, targets: list[str], **kwargs) -> list[CollectedFact]:
        facts: list[CollectedFact] = []
        for domain in targets:
            for category, template in _DORKS:
                query = template.format(d=domain)
                if query.startswith("http"):
                    link = query  # ja e uma URL (Wayback)
                else:
                    link = "https://www.google.com/search?q=" + quote_plus(query)
                facts.append(
                    CollectedFact(
                        target=domain, service="osint",
                        title=f"[Dork] {category}",
                        raw=f"{query}\n\nExecutar: {link}",
                        data={"severity_hint": "info", "category": category,
                              "query": query, "link": link, "source": "google_dork"},
                    )
                )
        return facts
