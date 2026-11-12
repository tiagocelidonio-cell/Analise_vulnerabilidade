"""Pipeline de scan rodando em background (ARQ).

Fluxo: coletar fatos -> virar Finding+Evidence -> enriquecer -> IA avalia.
A IA entra por ultimo e so raciocina sobre o que foi provado.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from arq.connections import RedisSettings
from sqlalchemy import select

from app.ai.agent import analyst
from app.collectors import COLLECTORS, DEFAULT_COLLECTORS
from app.config import settings
from app.db import SessionLocal, init_db
from app.enrichment.cve_match import correlate
from app.enrichment.sources import enrich_cves
from app.models import Evidence, Finding, ScanJob, ScanStatus, Severity
from app.scope import validate_targets
from app.targets import expand_targets


async def run_scan(ctx: dict, scan_id: str) -> dict:
    async with SessionLocal() as session:
        scan = await session.get(ScanJob, scan_id)
        if scan is None:
            return {"error": "scan nao encontrado"}

        from app.models import Engagement
        eng = await session.get(Engagement, scan.engagement_id)

        # Defesa em profundidade: revalida escopo no worker.
        if eng is None or not eng.authorized:
            scan.status = ScanStatus.failed
            scan.error = "engagement nao autorizado"
            await session.commit()
            return {"error": scan.error}

        out = validate_targets(scan.targets, eng.scope)
        if out:
            scan.status = ScanStatus.failed
            scan.error = f"alvos fora do escopo: {out}"
            await session.commit()
            return {"error": scan.error}

        scan.status = ScanStatus.running
        scan.phase = "iniciando"
        scan.progress = 2
        await session.commit()

        async def _cancelled() -> bool:
            return bool(await session.scalar(
                select(ScanJob.cancel_requested).where(ScanJob.id == scan.id)))

        async def _finish_cancelled():
            scan.status = ScanStatus.cancelled
            scan.phase = "cancelado"
            scan.finished_at = datetime.now(timezone.utc)
            await session.commit()

        try:
            selected = scan.collectors or DEFAULT_COLLECTORS
            # Coletores de host recebem os IPs expandidos do range; os de
            # recon (dominio) recebem os alvos originais.
            host_targets = expand_targets(scan.targets)
            # nmap (port_scan) lida com ranges nativamente -> recebe alvos crus.
            # Os coletores Python de host precisam dos IPs expandidos.
            host_collectors = {"http_probe", "web_content", "web_vuln"}
            facts = []
            for i, name in enumerate(selected):
                if await _cancelled():
                    await _finish_cancelled()
                    return {"cancelled": True}
                collector = COLLECTORS.get(name)
                if collector is None:
                    continue
                scan.phase = f"coletando: {name}"
                await session.commit()
                tlist = host_targets if name in host_collectors else scan.targets
                # Coletores de host em lotes -> permite cancelar no meio e
                # atualizar progresso enquanto varre muitos IPs.
                if name in host_collectors and len(tlist) > 16:
                    for j in range(0, len(tlist), 16):
                        if await _cancelled():
                            await _finish_cancelled()
                            return {"cancelled": True}
                        batch = tlist[j:j + 16]
                        facts.extend(await collector.run(batch, ports=scan.ports or None))
                        frac = (j + len(batch)) / len(tlist)
                        scan.phase = f"coletando: {name} ({int(frac * 100)}%)"
                        scan.progress = 5 + int(40 * (i + frac) / max(len(selected), 1))
                        await session.commit()
                else:
                    facts.extend(await collector.run(tlist, ports=scan.ports or None))
                # coleta ocupa ate 45% do progresso
                scan.progress = 5 + int(40 * (i + 1) / max(len(selected), 1))
                await session.commit()

            total = max(len(facts), 1)
            scan.phase = f"analisando {len(facts)} achado(s)"
            scan.progress = 50
            await session.commit()

            created = 0
            for n, fact in enumerate(facts):
                if n % 20 == 0 and await _cancelled():
                    await _finish_cancelled()
                    return {"cancelled": True}
                fact_dict = asdict(fact)
                now = datetime.now(timezone.utc)
                # Assinatura para deduplicar o mesmo achado entre scans.
                signature = f"{fact.target}|{fact.port}|{fact.title}".lower()

                # 1) CVEs: nuclei ja traz os CVEs; senao, correlaciona o banner (NVD).
                if fact.data.get("cve_ids"):
                    cve_ids = fact.data["cve_ids"]
                    correlation = {"cve_ids": cve_ids,
                                   "max_cvss": fact.data.get("cvss")}
                else:
                    correlation = await correlate(fact.data.get("banner", "") or fact.raw)
                    cve_ids = correlation["cve_ids"]
                fact_dict["correlation"] = correlation

                # 2) Enriquece esses CVEs com EPSS (probabilidade) e KEV (exploracao ativa).
                enrichment = await enrich_cves(cve_ids) if cve_ids else {
                    "epss": {}, "kev": {}, "max_epss": 0.0, "any_kev": False
                }

                # 3) IA raciocina sobre os fatos ja provados.
                assessment = await analyst.assess(fact_dict, enrichment)

                # Dedup: ja existe esse achado neste cliente? Entao so atualiza
                # (persiste apos rescan), sem duplicar.
                existing = await session.scalar(
                    select(Finding).where(
                        Finding.engagement_id == eng.id,
                        Finding.signature == signature,
                    )
                )
                if existing is not None:
                    existing.times_seen += 1
                    existing.last_seen = now
                    existing.scan_id = scan.id
                    existing.severity = Severity(assessment.severity)
                    existing.cvss = correlation.get("max_cvss")
                    existing.epss = enrichment.get("max_epss") or None
                    existing.in_kev = enrichment.get("any_kev", False)
                else:
                    finding = Finding(
                        engagement_id=eng.id,
                        scan_id=scan.id,
                        target=fact.target,
                        port=fact.port,
                        service=fact.service,
                        title=fact.title,
                        description=assessment.risk_summary,
                        severity=Severity(assessment.severity),
                        cvss=correlation.get("max_cvss"),
                        epss=enrichment.get("max_epss") or None,
                        in_kev=enrichment.get("any_kev", False),
                        cve_ids=cve_ids,
                        ai_assessment=assessment.to_dict(),
                        confidence=assessment.confidence,
                        signature=signature,
                        times_seen=1,
                        last_seen=now,
                    )
                    session.add(finding)
                    await session.flush()  # garante finding.id
                    session.add(
                        Evidence(
                            finding_id=finding.id,
                            kind="raw",
                            content=fact.raw[:4000] if fact.raw else fact.title,
                        )
                    )
                    created += 1
                # analise ocupa de 50% a 95%
                if n % 5 == 0:
                    scan.progress = 50 + int(45 * (n + 1) / total)
                    scan.findings_count = created
                    await session.commit()

            if await _cancelled():
                await _finish_cancelled()
                return {"cancelled": True}

            # Resumo amigavel do que foi encontrado (estilo "4 subdominios").
            parts = []
            subs = sum(1 for f in facts if f.service == "subdomain")
            ports = sum(1 for f in facts if "aberta" in (f.title or "").lower())
            web = sum(1 for f in facts if f.service in ("http", "https"))
            ot = sum(1 for f in facts if (f.data or {}).get("ot"))
            if subs:
                parts.append(f"{subs} subdomínios")
            if ports:
                parts.append(f"{ports} portas abertas")
            if web:
                parts.append(f"{web} serviços web")
            if ot:
                parts.append(f"{ot} OT/IoT")
            scan.summary = ", ".join(parts) or f"{created} achados"

            scan.status = ScanStatus.completed
            scan.phase = "concluido"
            scan.progress = 100
            scan.findings_count = created
            scan.finished_at = datetime.now(timezone.utc)
            await session.commit()
            return {"findings": created}

        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.failed
            scan.error = str(exc)
            await session.commit()
            return {"error": str(exc)}


async def _startup(ctx: dict) -> None:
    await init_db()
    # Scans que ficaram "running" sao orfaos de um worker anterior: encerra.
    async with SessionLocal() as session:
        orphans = await session.scalars(
            select(ScanJob).where(ScanJob.status == ScanStatus.running))
        for s in orphans:
            s.status = ScanStatus.cancelled
            s.phase = "interrompido (worker reiniciado)"
        await session.commit()


class WorkerSettings:
    functions = [run_scan]
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    on_startup = _startup
    max_jobs = 10
