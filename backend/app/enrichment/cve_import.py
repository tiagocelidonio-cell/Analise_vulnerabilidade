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

import asyncio
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
from app.models import (
    CveImportStatus,
    CveRemediation,
    CveScheduleConfig,
    Finding,
)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE = 2000  # maximo da NVD por pagina


async def get_import_status(session: AsyncSession) -> CveImportStatus:
    st = await session.get(CveImportStatus, "main")
    if st is None:
        st = CveImportStatus(id="main")
        session.add(st)
        await session.commit()
        await session.refresh(st)
    return st


def import_status_dict(st: CveImportStatus) -> dict:
    pct = int(100 * st.processed / st.total) if st.total else (100 if st.state == "done" else 0)
    return {
        "state": st.state, "phase": st.phase, "total": st.total,
        "processed": st.processed, "imported": st.imported, "percent": pct,
        "source": st.source, "error": st.error,
        "running": st.state in ("connecting", "downloading"),
        "started_at": st.started_at.isoformat() if st.started_at else None,
        "updated_at": st.updated_at.isoformat() if st.updated_at else None,
        "finished_at": st.finished_at.isoformat() if st.finished_at else None,
    }


def _parse_nvd_vuln(item: dict) -> dict | None:
    cve = (item or {}).get("cve") or {}
    cid = cve.get("id")
    if not cid:
        return None
    descs = cve.get("descriptions") or []
    desc = next((d.get("value") for d in descs if d.get("lang", "").startswith("en")), "")
    refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")][:8]
    cvss = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                cvss = float(arr[0]["cvssData"]["baseScore"])
                break
            except (KeyError, IndexError, ValueError, TypeError):
                continue
    return {"cve_id": cid, "description": (desc or "")[:400] or None,
            "references": refs, "cvss": cvss, "solution": _SOLUTION_BASE}


async def import_full_nvd(session: AsyncSession) -> dict:
    """Baixa a base completa de CVE pela API oficial da NVD, PAGINADA e
    MONITORADA. Atualiza CveImportStatus a cada pagina (progresso, conexao,
    erro) e respeita cancelamento. Resiliente a rate-limit (429/403)."""
    st = await get_import_status(session)
    st.state = "connecting"
    st.phase = "conectando à NVD…"
    st.error = None
    st.cancel_requested = False
    st.total = 0
    st.processed = 0
    st.imported = 0
    st.source = "NVD 2.0 API" + (" (com chave)" if settings.nvd_api_key else " (sem chave)")
    st.started_at = datetime.now(timezone.utc)
    st.updated_at = st.started_at
    st.finished_at = None
    await session.commit()

    headers = {"User-Agent": "VulnScope"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    # Sem chave: 5 req/30s -> ~6s entre chamadas. Com chave: ~0.8s.
    delay = 0.8 if settings.nvd_api_key else 6.5

    async def _cancelled() -> bool:
        v = await session.scalar(
            select(CveImportStatus.cancel_requested).where(CveImportStatus.id == "main"))
        return bool(v)

    async def _fail(msg: str) -> dict:
        st.state = "error"
        st.phase = "erro"
        st.error = msg[:500]
        st.finished_at = datetime.now(timezone.utc)
        st.updated_at = st.finished_at
        await session.commit()
        return {"error": msg, "imported": st.imported}

    start = 0
    imported = 0
    processed = 0
    async with httpx.AsyncClient(timeout=60, headers=headers) as client:
        while True:
            if await _cancelled():
                st.state = "cancelled"
                st.phase = "cancelado pelo usuário"
                st.finished_at = datetime.now(timezone.utc)
                st.updated_at = st.finished_at
                await session.commit()
                return {"cancelled": True, "imported": imported}

            params = {"resultsPerPage": _PAGE, "startIndex": start}
            data = None
            # Ate 4 tentativas por pagina (rate-limit/instabilidade).
            for attempt in range(4):
                try:
                    r = await client.get(NVD_URL, params=params)
                except (httpx.HTTPError, OSError) as exc:
                    if attempt == 3:
                        return await _fail(f"Falha de conexão com a NVD: {exc}")
                    await asyncio.sleep(delay * (attempt + 1))
                    continue
                if r.status_code in (403, 429, 503):  # rate-limit/indisponivel
                    if attempt == 3:
                        return await _fail(
                            f"NVD recusou (HTTP {r.status_code}). Tente novamente mais "
                            f"tarde ou configure NVD_API_KEY.")
                    await asyncio.sleep(delay * (attempt + 2))
                    continue
                if r.status_code >= 400:
                    return await _fail(f"NVD retornou HTTP {r.status_code}.")
                try:
                    data = r.json()
                except ValueError:
                    return await _fail("Resposta inválida da NVD (JSON).")
                break
            if data is None:
                return await _fail("Não foi possível obter dados da NVD.")

            total = int(data.get("totalResults") or 0)
            vulns = data.get("vulnerabilities") or []
            if start == 0:
                st.total = total
                st.state = "downloading"
            # Grava os registros da pagina.
            for item in vulns:
                rec = _parse_nvd_vuln(item)
                processed += 1
                if rec is None:
                    continue
                await _upsert(session, rec)
                imported += 1
            st.processed = processed
            st.imported = imported
            st.phase = (f"baixando {processed}/{total} "
                        f"({int(100 * processed / total) if total else 0}%)")
            st.updated_at = datetime.now(timezone.utc)
            await session.commit()

            start += _PAGE
            if start >= total or not vulns:
                break
            await asyncio.sleep(delay)  # respeita o limite da NVD

    st.state = "done"
    st.phase = f"concluído: {imported} CVEs"
    st.finished_at = datetime.now(timezone.utc)
    st.updated_at = st.finished_at
    await session.commit()
    return {"imported": imported, "total": st.total}


async def get_schedule(session: AsyncSession) -> CveScheduleConfig:
    """Le a config de agenda (cria na 1a vez, semeando do env)."""
    cfg = await session.get(CveScheduleConfig, "cve")
    if cfg is None:
        hours = settings.cve_update_interval_hours
        cfg = CveScheduleConfig(
            id="cve", enabled=hours > 0,
            interval_hours=hours if hours > 0 else 24, full=False)
        session.add(cfg)
        await session.commit()
        await session.refresh(cfg)
    return cfg

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
