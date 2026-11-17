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


# Sem atualizacao por mais que isto, com estado "em andamento", = travado
# (worker morto/reiniciado no meio). Folga generosa p/ nao marcar durante
# retries de rate-limit (sem chave a NVD e lenta). Veja _startup no worker.
STALE_SECONDS = 180


def import_status_dict(st: CveImportStatus) -> dict:
    pct = int(100 * st.processed / st.total) if st.total else (100 if st.state == "done" else 0)
    running = st.state in ("connecting", "downloading")
    stale_seconds = None
    stale = False
    if running and st.updated_at is not None:
        upd = st.updated_at
        if upd.tzinfo is None:
            upd = upd.replace(tzinfo=timezone.utc)
        stale_seconds = int((datetime.now(timezone.utc) - upd).total_seconds())
        stale = stale_seconds > STALE_SECONDS
    return {
        "state": st.state, "phase": st.phase, "total": st.total,
        "processed": st.processed, "imported": st.imported, "percent": pct,
        "source": st.source, "error": st.error,
        "running": running,
        "stale": stale, "stale_seconds": stale_seconds,
        "log": st.log or [],
        "started_at": st.started_at.isoformat() if st.started_at else None,
        "updated_at": st.updated_at.isoformat() if st.updated_at else None,
        "finished_at": st.finished_at.isoformat() if st.finished_at else None,
    }


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _cpe_products(cve: dict) -> list[str]:
    """Extrai 'vendor product' (normalizado) das configuracoes CPE do CVE.

    Ex.: cpe:2.3:a:apache:http_server:2.4.* -> 'apache http server'. Serve para
    cruzar o CVE com as tecnologias detectadas nos ativos do cliente."""
    out: list[str] = []
    seen: set[str] = set()
    for conf in cve.get("configurations") or []:
        nodes = conf.get("nodes") if isinstance(conf, dict) else None
        for node in nodes or []:
            for m in node.get("cpeMatch") or []:
                crit = (m.get("criteria") or "").replace("\\", "")
                parts = crit.split(":")
                if len(parts) < 5:
                    continue
                vendor, product = parts[3], parts[4]
                if product in ("*", "-", ""):
                    continue
                label = f"{vendor} {product}".replace("_", " ").strip().lower()
                if label and label not in seen:
                    seen.add(label)
                    out.append(label)
                    if len(out) >= 40:
                        return out
    return out


def _cpe_rules(cve: dict) -> list[dict]:
    """Regras CPE com faixa de versao afetada, para match por produto+versao.

    Cada regra: {prod:'vendor:product', ver:'<exata ou vazia>', vs,vsi,ve,vei}.
    vs/ve = inicio/fim; vsi/vei = se o limite e' inclusivo."""
    out: list[dict] = []
    seen: set = set()
    for conf in cve.get("configurations") or []:
        nodes = conf.get("nodes") if isinstance(conf, dict) else None
        for node in nodes or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") is False:
                    continue
                parts = (m.get("criteria") or "").replace("\\", "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product, ver = parts[3], parts[4], parts[5]
                if product in ("*", "-", ""):
                    continue
                rule = {
                    "prod": f"{vendor}:{product}".lower(),
                    "ver": ver if ver not in ("*", "-") else "",
                    "vs": m.get("versionStartIncluding") or m.get("versionStartExcluding") or "",
                    "vsi": bool(m.get("versionStartIncluding")),
                    "ve": m.get("versionEndIncluding") or m.get("versionEndExcluding") or "",
                    "vei": bool(m.get("versionEndIncluding")),
                }
                key = (rule["prod"], rule["ver"], rule["vs"], rule["ve"])
                if key in seen:
                    continue
                seen.add(key)
                out.append(rule)
                if len(out) >= 30:
                    return out
    return out


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
            "references": refs, "cvss": cvss, "solution": _SOLUTION_BASE,
            "products": _cpe_products(cve), "cpe": _cpe_rules(cve),
            "published": _parse_dt(cve.get("published"))}


async def import_full_nvd(session: AsyncSession, resume: bool = False,
                          max_pages: int = 12) -> dict:
    """Baixa a base de CVE da NVD 2.0 em LOTES pequenos e resumíveis.

    Em vez de um job gigante (frágil a reinício), processa no máximo `max_pages`
    páginas por invocação e retorna {"incomplete": True} quando ainda há mais —
    o worker re-enfileira a continuação. Assim cada execução é curta (<~2 min),
    o progresso é salvo a cada página, e um reinício perde no máximo um lote.

    resume=True: RETOMA de onde parou (borda de página; upsert idempotente)."""
    st = await get_import_status(session)
    now0 = datetime.now(timezone.utc)
    if resume and st.processed and st.total:
        resume_start = (st.processed // _PAGE) * _PAGE
        base_imported = st.imported or resume_start
        st.state = "downloading"
        st.phase = f"retomando em {st.processed}/{st.total}…"
        st.error = None
        st.cancel_requested = False
        st.finished_at = None
        st.updated_at = now0
        if st.started_at is None:
            st.started_at = now0
        await session.commit()
    else:
        resume_start = 0
        base_imported = 0
        st.state = "connecting"
        st.phase = "conectando à NVD…"
        st.error = None
        st.cancel_requested = False
        st.total = 0
        st.processed = 0
        st.imported = 0
        st.source = "NVD 2.0 API" + (" (com chave)" if settings.nvd_api_key else " (sem chave)")
        st.started_at = now0
        st.updated_at = now0
        st.finished_at = None
        st.log = []  # novo download -> zera o console
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

    def _ilog(msg: str, level: str = "info") -> None:
        st.log = ((st.log or []) + [{
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level, "msg": str(msg)[:400]}])[-200:]

    _ilog(f"{'retomando' if resume else 'iniciando'} download — "
          f"{st.source}; página de {_PAGE} CVEs; a partir de startIndex={resume_start}")

    start = resume_start
    imported = base_imported
    processed = resume_start
    pages_done = 0
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
            _ilog(f"$ GET {NVD_URL}?startIndex={start}&resultsPerPage={_PAGE}")
            data = None
            # Ate 4 tentativas por pagina (rate-limit/instabilidade).
            for attempt in range(4):
                try:
                    r = await client.get(NVD_URL, params=params)
                except (httpx.HTTPError, OSError) as exc:
                    if attempt == 3:
                        _ilog(f"falha de conexão com a NVD: {exc}", "error")
                        return await _fail(f"Falha de conexão com a NVD: {exc}")
                    _ilog(f"erro de rede (tentativa {attempt + 1}/4), aguardando…", "warn")
                    await asyncio.sleep(delay * (attempt + 1))
                    continue
                if r.status_code in (403, 429, 503):  # rate-limit/indisponivel
                    if attempt == 3:
                        _ilog(f"NVD recusou (HTTP {r.status_code})", "error")
                        return await _fail(
                            f"NVD recusou (HTTP {r.status_code}). Tente novamente mais "
                            f"tarde ou configure NVD_API_KEY.")
                    _ilog(f"rate-limit (HTTP {r.status_code}), aguardando "
                          f"{delay * (attempt + 2):.0f}s… (configure NVD_API_KEY p/ acelerar)", "warn")
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
            _ilog(f"  página OK: +{len(vulns)} CVE(s) → {processed}/{total} "
                  f"({int(100 * processed / total) if total else 0}%)")
            st.updated_at = datetime.now(timezone.utc)
            await session.commit()

            start += _PAGE
            if start >= total or not vulns:
                break
            pages_done += 1
            if pages_done >= max_pages:
                # Lote cheio: salva e devolve o controle p/ o worker re-enfileirar
                # a continuação. Mantém o estado "baixando" (não é fim nem erro).
                st.phase = (f"baixando {processed}/{total} "
                            f"({int(100 * processed / total) if total else 0}%)")
                _ilog(f"lote salvo em {processed}/{total} — re-enfileirando a "
                      f"continuação (download robusto em lotes)")
                st.updated_at = datetime.now(timezone.utc)
                await session.commit()
                return {"incomplete": True, "imported": imported,
                        "processed": processed, "total": total}
            await asyncio.sleep(delay)  # respeita o limite da NVD

    st.state = "done"
    st.phase = f"concluído: {imported} CVEs"
    _ilog(f"★ concluído: {imported} CVE(s) importado(s).")
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
    # Produtos afetados (CVE 5.0): containers.cna.affected[].vendor/product.
    prods: list[str] = []
    seen: set[str] = set()
    for aff in cna.get("affected") or []:
        vendor = (aff.get("vendor") or "").strip()
        product = (aff.get("product") or "").strip()
        if not product or product.lower() in ("n/a", "unspecified", "*"):
            continue
        label = f"{vendor} {product}".replace("_", " ").strip().lower()
        if label and label not in seen:
            seen.add(label)
            prods.append(label)
            if len(prods) >= 40:
                break
    return {
        "cve_id": cve_id,
        "description": (desc or "")[:400] or None,
        "references": refs,
        "cvss": cvss,
        "solution": _SOLUTION_BASE,
        "products": prods,
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
    if rec.get("products"):
        row.products = rec["products"]
    if rec.get("cpe"):
        row.cpe = rec["cpe"]
    if rec.get("published") is not None:
        row.published = rec["published"]
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


def _sev_from_cvss(cvss) -> str:
    if cvss is None:
        return "info"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


async def recent_cves(session: AsyncSession, limit: int = 30) -> list[dict]:
    """Feed dos CVEs mais recentes.

    Prefere data de PUBLICACAO (import NVD 2.0 a captura). CVEs sem data
    (import por bundle) NAO sao mais excluidos: caem para a data de importacao,
    ordenados depois dos publicados. Assim o feed nunca fica vazio so porque os
    registros vieram sem 'published'."""
    from sqlalchemy import func as _func
    lim = min(limit, 100)
    # published desc NULLS LAST, depois updated_at desc.
    rows = list(await session.scalars(
        select(CveRemediation)
        .order_by(_func.coalesce(CveRemediation.published, CveRemediation.updated_at).desc())
        .limit(lim)))
    return [{
        "cve_id": r.cve_id, "cvss": r.cvss, "severity": _sev_from_cvss(r.cvss),
        "description": r.description,
        "products": (r.products or [])[:6],
        "published": r.published.isoformat() if r.published else None,
    } for r in rows]


async def base_status(session: AsyncSession) -> dict:
    count = await session.scalar(select(func.count()).select_from(CveRemediation))
    last = await session.scalar(select(func.max(CveRemediation.updated_at)))
    return {"count": int(count or 0),
            "last_updated": last.isoformat() if last else None}
