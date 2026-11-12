"""Atualizacao da BASE LOCAL de CVE.

Dois modos:
  - refresh_seen(): leve. Re-busca a remediacao (NVD, cacheada) dos CVEs que ja
    aparecem nos achados. Barato e relevante. E o que a agenda roda.
  - import_from_bundle(): pesado. Baixa o bundle OFICIAL da CVE List (JSON 5.0,
    cve.org / CVEProject) e importa TODOS os registros para a tabela local
    cve_remediation (descricao, referencias/patch, CVSS). Deixa a base 100%
    local (sem depender da NVD por CVE). Rode sob demanda (pode ser grande).

Fonte oficial do bundle: https://www.cve.org/Downloads (CVE List JSON 5.0).
A URL e configuravel em settings.cve_feed_url.
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import CveRemediation, Finding

_SOLUTION_BASE = (
    "Aplicar as correcoes/patches do fabricante e atualizar o componente "
    "afetado para a versao corrigida."
)


def _cvss_from_metrics(metrics: list) -> float | None:
    """Extrai o maior baseScore dos metrics do CVE JSON 5.0."""
    best = None
    for m in metrics or []:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            cv = m.get(key)
            if cv and isinstance(cv, dict) and cv.get("baseScore") is not None:
                try:
                    v = float(cv["baseScore"])
                    best = v if best is None else max(best, v)
                except (TypeError, ValueError):
                    pass
    return best


def parse_cve_record(obj: dict) -> dict | None:
    """CVE JSON 5.0 -> {cve_id, description, references, cvss}. None se invalido."""
    meta = obj.get("cveMetadata") or {}
    cve_id = meta.get("cveId")
    if not cve_id:
        return None
    cna = (obj.get("containers") or {}).get("cna") or {}
    descs = cna.get("descriptions") or []
    desc = next((d.get("value") for d in descs if d.get("lang", "").startswith("en")), "")
    if not desc and descs:
        desc = descs[0].get("value", "")
    refs = [r.get("url") for r in (cna.get("references") or []) if r.get("url")][:8]
    cvss = _cvss_from_metrics(cna.get("metrics") or [])
    return {
        "cve_id": cve_id,
        "description": (desc or "")[:400] or None,
        "references": refs,
        "cvss": cvss,
        "solution": _SOLUTION_BASE,
    }


async def _upsert(session: AsyncSession, rec: dict) -> None:
    row = await session.get(CveRemediation, rec["cve_id"])
    if row is None:
        row = CveRemediation(cve_id=rec["cve_id"])
        session.add(row)
    row.solution = rec["solution"]
    row.references = rec["references"]
    row.cvss = rec["cvss"]
    row.description = rec["description"]
    row.updated_at = datetime.now(timezone.utc)


async def import_from_bundle(
    session: AsyncSession, url: str | None = None, limit: int | None = None,
) -> dict:
    """Baixa o bundle oficial e importa os registros. Retorna {imported, skipped}."""
    url = url or settings.cve_feed_url
    imported = skipped = 0
    tmp_path = None
    try:
        # Baixa em streaming para um arquivo temporario (bundle pode ser grande).
        with tempfile.NamedTemporaryFile("wb", suffix=".zip", delete=False) as tf:
            tmp_path = tf.name
            async with httpx.AsyncClient(timeout=None, follow_redirects=True) as client:
                async with client.stream("GET", url) as resp:
                    resp.raise_for_status()
                    async for chunk in resp.aiter_bytes(1 << 20):
                        tf.write(chunk)

        with zipfile.ZipFile(tmp_path) as zf:
            names = [n for n in zf.namelist()
                     if n.endswith(".json") and "/CVE-" in ("/" + n)]
            for name in names:
                if limit is not None and imported >= limit:
                    break
                try:
                    with zf.open(name) as fh:
                        obj = json.load(io.TextIOWrapper(fh, encoding="utf-8"))
                    rec = parse_cve_record(obj)
                except (json.JSONDecodeError, KeyError, OSError):
                    rec = None
                if rec is None:
                    skipped += 1
                    continue
                await _upsert(session, rec)
                imported += 1
                if imported % 2000 == 0:
                    await session.commit()
            await session.commit()
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return {"imported": imported, "skipped": skipped, "source": url}


async def refresh_seen(session: AsyncSession) -> dict:
    """Re-busca remediacao (NVD, cacheada) dos CVEs presentes nos achados."""
    from app.enrichment.remediation import get_remediation

    rows = await session.scalars(select(Finding.cve_ids))
    cves: set[str] = set()
    for arr in rows:
        for c in (arr or []):
            cves.add(c)
    updated = 0
    for cid in cves:
        try:
            if await get_remediation(session, cid):
                updated += 1
        except Exception:  # noqa: BLE001
            continue
    await session.commit()
    return {"updated": updated, "total_seen": len(cves)}


async def base_status(session: AsyncSession) -> dict:
    count = await session.scalar(select(func.count()).select_from(CveRemediation))
    last = await session.scalar(select(func.max(CveRemediation.updated_at)))
    return {"count": int(count or 0),
            "last_updated": last.isoformat() if last else None}
