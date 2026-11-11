"""Enriquecimento com fontes publicas e gratuitas.

- EPSS (FIRST): probabilidade de exploracao nos proximos 30 dias.
- CISA KEV: catalogo do que ja esta sendo explorado na vida real.
- NVD: detalhes/CVSS do CVE (stub de interface aqui).

Tudo isso transforma "tem um CVE" em "isso e explorado ativamente agora".
Mantido resiliente: se a rede falhar, degrada sem derrubar o scan.
"""
from __future__ import annotations

import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_epss(cve_ids: list[str]) -> dict[str, float]:
    """Retorna {cve: score_epss}. Score alto = mais provavel de ser explorado."""
    if not cve_ids:
        return {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(EPSS_URL, params={"cve": ",".join(cve_ids)})
            resp.raise_for_status()
            data = resp.json().get("data", [])
            return {row["cve"]: float(row["epss"]) for row in data}
    except (httpx.HTTPError, ValueError, KeyError):
        return {}


_kev_cache: set[str] | None = None


async def fetch_kev_set() -> set[str]:
    """Conjunto de CVEs no catalogo KEV da CISA (cacheado em memoria)."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            _kev_cache = {v["cveID"] for v in vulns}
    except (httpx.HTTPError, ValueError, KeyError):
        _kev_cache = set()
    return _kev_cache


async def enrich_cves(cve_ids: list[str]) -> dict:
    """Junta EPSS + KEV para uma lista de CVEs."""
    epss = await fetch_epss(cve_ids)
    kev = await fetch_kev_set()
    return {
        "epss": epss,
        "kev": {cve: (cve in kev) for cve in cve_ids},
        "max_epss": max(epss.values(), default=0.0),
        "any_kev": any(cve in kev for cve in cve_ids),
    }
