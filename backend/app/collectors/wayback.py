"""Coletor Wayback Machine (CDX API) — OSINT passivo.

Lista URLs ja arquivadas do dominio e filtra extensoes sensiveis. Encontra,
de forma legitima e automatizavel, o mesmo que varios Google dorks buscam
(documentos, configs, backups, SQL, logs expostos) — sem raspar o Google.

Fonte: http://web.archive.org/cdx/search/cdx (API publica, sem auth).
"""
from __future__ import annotations

import httpx

from app.collectors.base import CollectedFact

CDX_URL = "http://web.archive.org/cdx/search/cdx"

# Extensao sensivel -> dica de severidade.
_SENSITIVE_EXT = {
    "sql": "high", "dbf": "high", "mdb": "high", "env": "high", "bak": "high",
    "backup": "high", "old": "medium", "bkp": "high", "bkf": "high",
    "conf": "medium", "cnf": "medium", "cfg": "medium", "ini": "medium",
    "yml": "medium", "yaml": "medium", "json": "low", "xml": "low",
    "log": "medium", "txt": "low", "doc": "low", "docx": "low", "xls": "low",
    "xlsx": "low", "csv": "low", "pdf": "info", "git": "high", "pem": "high",
    "key": "high", "rdp": "medium", "ora": "medium", "reg": "medium",
}


def _ext_of(url: str) -> str | None:
    path = url.split("?")[0].rstrip("/")
    last = path.rsplit("/", 1)[-1]
    if "." in last:
        return last.rsplit(".", 1)[-1].lower()
    return None


class WaybackCollector:
    name = "wayback"

    async def run(
        self, targets: list[str], limit: int = 5000, **kwargs
    ) -> list[CollectedFact]:
        facts: list[CollectedFact] = []
        for domain in targets:
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.get(
                        CDX_URL,
                        params={
                            "url": f"{domain}/*",
                            "output": "json",
                            "fl": "original",
                            "collapse": "urlkey",
                            "limit": limit,
                        },
                    )
                    resp.raise_for_status()
                    rows = resp.json()
            except (httpx.HTTPError, ValueError):
                continue

            # primeira linha e cabecalho ["original"]
            urls = [r[0] for r in rows[1:]] if rows and len(rows) > 1 else []
            seen: set[str] = set()
            for url in urls:
                ext = _ext_of(url)
                if ext in _SENSITIVE_EXT and url not in seen:
                    seen.add(url)
                    facts.append(
                        CollectedFact(
                            target=domain, service="osint",
                            title=f"Arquivo sensivel historico (.{ext}): {url[:90]}",
                            raw=url,
                            data={"severity_hint": _SENSITIVE_EXT[ext],
                                  "url": url, "ext": ext, "source": "wayback"},
                        )
                    )
        return facts
