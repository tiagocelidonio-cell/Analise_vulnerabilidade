"""Pipeline de scan rodando em background (ARQ).

Fluxo: coletar fatos -> virar Finding+Evidence -> enriquecer -> IA avalia.
A IA entra por ultimo e so raciocina sobre o que foi provado.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from arq.connections import RedisSettings

from app.ai.agent import analyst
from app.collectors import COLLECTORS, DEFAULT_COLLECTORS
from app.config import settings
from app.db import SessionLocal, init_db
from app.enrichment.cve_match import correlate
from app.enrichment.sources import enrich_cves
from app.models import Evidence, Finding, ScanJob, ScanStatus, Severity
from app.scope import validate_targets


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

        try:
            selected = scan.collectors or DEFAULT_COLLECTORS
            facts = []
            for i, name in enumerate(selected):
                collector = COLLECTORS.get(name)
                if collector is None:
                    continue
                scan.phase = f"coletando: {name}"
                await session.commit()
                facts.extend(
                    await collector.run(scan.targets, ports=scan.ports or None)
                )
                # coleta ocupa ate 45% do progresso
                scan.progress = 5 + int(40 * (i + 1) / max(len(selected), 1))
                await session.commit()

            total = max(len(facts), 1)
            scan.phase = f"analisando {len(facts)} achado(s)"
            scan.progress = 50
            await session.commit()

            created = 0
            for fact in facts:
                fact_dict = asdict(fact)

                # 1) Correlaciona o banner com CVEs reais (NVD).
                correlation = await correlate(fact.data.get("banner", "") or fact.raw)
                cve_ids = correlation["cve_ids"]
                fact_dict["correlation"] = correlation

                # 2) Enriquece esses CVEs com EPSS (probabilidade) e KEV (exploracao ativa).
                enrichment = await enrich_cves(cve_ids) if cve_ids else {
                    "epss": {}, "kev": {}, "max_epss": 0.0, "any_kev": False
                }

                # 3) IA raciocina sobre os fatos ja provados.
                assessment = await analyst.assess(fact_dict, enrichment)

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
                )
                session.add(finding)
                await session.flush()  # garante finding.id

                # Evidencia bruta e imutavel (o banner cru provando o achado).
                session.add(
                    Evidence(
                        finding_id=finding.id,
                        kind="raw",
                        content=fact.raw[:4000] if fact.raw else fact.title,
                    )
                )
                created += 1
                # analise ocupa de 50% a 95%
                if created % 5 == 0:
                    scan.progress = 50 + int(45 * created / total)
                    scan.findings_count = created
                    await session.commit()

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


class WorkerSettings:
    functions = [run_scan]
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    on_startup = _startup
    max_jobs = 10
