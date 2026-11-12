"""Remediacao por CVE a partir da NVD, com CACHE LOCAL no banco.

Herdado do sistema antigo (tihacks/intelligence/services.py), adaptado para
async + SQLAlchemy. Fluxo:
  1. tenta o cache (tabela cve_remediation); se fresco (< 30 dias), usa.
  2. senao, busca na NVD (1 CVE por vez), extrai solucao + links + CVSS,
     grava no cache e retorna.
Offline / rate-limit / erro: degrada sem derrubar o pipeline (usa o cache
mesmo velho, ou retorna vazio). Apos a 1a busca de cada CVE, fica LOCAL.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CveRemediation

NVD_ONE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_FRESH_DAYS = 30
_SEM = asyncio.Semaphore(1)  # NVD sem chave: serializa + espaca as chamadas
_MIN_INTERVAL = 0.8
_last = {"t": 0.0}

_SOLUTION_BASE = (
    "Aplicar as correcoes/patches do fabricante e atualizar o componente "
    "afetado para a versao corrigida."
)


def _extract_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                return float(arr[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, ValueError, TypeError):
                continue
    return None


async def _fetch_nvd(cve_id: str) -> dict | None:
    async with _SEM:
        # Espaca as chamadas para respeitar o limite da NVD sem chave.
        now = asyncio.get_event_loop().time()
        wait = _MIN_INTERVAL - (now - _last["t"])
        if wait > 0:
            await asyncio.sleep(wait)
        _last["t"] = asyncio.get_event_loop().time()
        try:
            async with httpx.AsyncClient(timeout=12) as client:
                resp = await client.get(NVD_ONE, params={"cveId": cve_id})
                if resp.status_code in (403, 429):
                    await asyncio.sleep(6)
                    resp = await client.get(NVD_ONE, params={"cveId": cve_id})
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, ValueError):
            return None

    vulns = data.get("vulnerabilities") or []
    if not vulns or not vulns[0].get("cve"):
        return {"solution": _SOLUTION_BASE, "references": [], "cvss": None,
                "description": None}
    cve = vulns[0]["cve"]
    refs = [r["url"] for r in cve.get("references", []) if r.get("url")][:8]
    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    return {
        "solution": _SOLUTION_BASE,
        "references": refs,
        "cvss": _extract_cvss(cve.get("metrics", {})),
        "description": desc[:400] or None,
    }


async def get_remediation(session: AsyncSession, cve_id: str) -> dict | None:
    """Retorna {solution, references, cvss, description} para um CVE (cacheado)."""
    if not cve_id:
        return None
    row = await session.get(CveRemediation, cve_id)
    if row is not None:
        age = datetime.now(timezone.utc) - (row.updated_at or datetime.now(timezone.utc))
        if age.days < _FRESH_DAYS:
            return {"solution": row.solution, "references": row.references or [],
                    "cvss": row.cvss, "description": row.description}

    fetched = await _fetch_nvd(cve_id)
    if fetched is None:
        # Offline/erro: usa o que tiver no cache (mesmo velho), senao nada.
        if row is not None:
            return {"solution": row.solution, "references": row.references or [],
                    "cvss": row.cvss, "description": row.description}
        return None

    # Grava/atualiza o cache (base local).
    if row is None:
        row = CveRemediation(cve_id=cve_id)
        session.add(row)
    row.solution = fetched["solution"]
    row.references = fetched["references"]
    row.cvss = fetched["cvss"]
    row.description = fetched["description"]
    row.updated_at = datetime.now(timezone.utc)
    return fetched
