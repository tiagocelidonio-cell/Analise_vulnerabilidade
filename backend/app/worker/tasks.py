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
from app.collectors import COLLECTORS, DEFAULT_COLLECTORS, HOST_COLLECTORS
from app.config import settings
from app.db import SessionLocal, init_db
from app.enrichment.cve_match import correlate
from app.enrichment.remediation import get_remediation
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
        scan.heartbeat = datetime.now(timezone.utc)
        await session.commit()

        import time as _time
        _beat_state = {"t": 0.0}

        async def _beat(phase: str | None = None) -> None:
            """Batimento: marca que o scan esta VIVO (mesmo em processo longo).
            Throttle de 4s para nao martelar o banco."""
            nowm = _time.monotonic()
            if phase is None and (nowm - _beat_state["t"]) < 4:
                return
            _beat_state["t"] = nowm
            try:
                scan.heartbeat = datetime.now(timezone.utc)
                if phase:
                    scan.phase = phase
                await session.commit()
            except Exception:  # noqa: BLE001  batimento nunca derruba o scan
                pass

        async def _control() -> str | None:
            """Le as flags frescas do banco: 'cancel', 'pause' ou None."""
            row = (await session.execute(
                select(ScanJob.cancel_requested, ScanJob.pause_requested)
                .where(ScanJob.id == scan.id)
            )).first()
            if row is None:
                return None
            if row[0]:
                return "cancel"
            if row[1]:
                return "pause"
            return None

        async def _finish_cancelled():
            scan.status = ScanStatus.cancelled
            scan.phase = "cancelado"
            scan.finished_at = datetime.now(timezone.utc)
            await session.commit()

        async def _finish_paused():
            # Preserva progresso e achados ja gravados; nao marca finished_at.
            scan.status = ScanStatus.paused
            scan.phase = "pausado"
            await session.commit()

        async def _halted() -> bool:
            """Checkpoint: trata cancel/pause. Retorna True se deve parar."""
            ctrl = await _control()
            if ctrl == "cancel":
                await _finish_cancelled()
                return True
            if ctrl == "pause":
                await _finish_paused()
                return True
            return False

        async def _abort_check() -> bool:
            # Passado aos coletores (nmap/nuclei) p/ MATAR o processo no meio.
            return (await _control()) is not None

        prof = scan.profile or "full"

        try:
            selected = scan.collectors or DEFAULT_COLLECTORS

            # --- Scan de VALIDACAO (SAFE / avancada) roda em background aqui ---
            if selected and selected[0] in ("validate", "validate_intrusive"):
                from app.exploitation.engine import run_validation
                intrusive = selected[0] == "validate_intrusive"
                scan.phase = "validando"
                scan.progress = 10
                scan.heartbeat = datetime.now(timezone.utc)
                await session.commit()

                async def _vprog(frac: float, phase: str) -> None:
                    scan.progress = 10 + int(80 * frac)
                    scan.phase = phase
                    scan.heartbeat = datetime.now(timezone.utc)
                    try:
                        await session.commit()
                    except Exception:  # noqa: BLE001
                        pass

                res = await run_validation(
                    session, eng.id, intrusive=intrusive,
                    targets=scan.targets or None,
                    on_progress=_vprog, cancel=_abort_check,
                )
                if await _halted():
                    return {"halted": True}
                conf = res.get("confirmed", 0)
                tgts = res.get("tested_targets", 0)
                scan.summary = f"{conf} confirmada(s) em {tgts} alvo(s)"
                scan.findings_count = conf
                scan.status = ScanStatus.completed
                scan.phase = "concluido"
                scan.progress = 100
                scan.heartbeat = datetime.now(timezone.utc)
                scan.finished_at = datetime.now(timezone.utc)
                await session.commit()
                return res
            # Coletores de host recebem os IPs expandidos do range; os de
            # recon (dominio) recebem os alvos originais.
            host_targets = expand_targets(scan.targets)
            # Todos os coletores de host rodam em LOTES de IPs: permite cancelar
            # no meio (inclusive o nmap) e mostrar progresso real.
            host_collectors = HOST_COLLECTORS
            facts = []
            for i, name in enumerate(selected):
                if await _halted():
                    return {"halted": True}
                collector = COLLECTORS.get(name)
                if collector is None:
                    continue
                scan.phase = f"coletando: {name}"
                scan.heartbeat = datetime.now(timezone.utc)
                await session.commit()
                tlist = host_targets if name in host_collectors else scan.targets
                # Coletores de host em lotes -> permite cancelar no meio e
                # atualizar progresso enquanto varre muitos IPs.
                if name in host_collectors and len(tlist) > 16:
                    for j in range(0, len(tlist), 16):
                        if await _halted():
                            return {"halted": True}
                        batch = tlist[j:j + 16]
                        facts.extend(await collector.run(
                            batch, ports=scan.ports or None,
                            profile=prof, cancel_check=_abort_check, on_tick=_beat))
                        frac = (j + len(batch)) / len(tlist)
                        scan.phase = f"coletando: {name} ({int(frac * 100)}%)"
                        scan.progress = 5 + int(40 * (i + frac) / max(len(selected), 1))
                        scan.heartbeat = datetime.now(timezone.utc)
                        await session.commit()
                else:
                    facts.extend(await collector.run(
                        tlist, ports=scan.ports or None,
                        profile=prof, cancel_check=_abort_check, on_tick=_beat))
                # coleta ocupa ate 45% do progresso
                scan.progress = 5 + int(40 * (i + 1) / max(len(selected), 1))
                scan.heartbeat = datetime.now(timezone.utc)
                await session.commit()

            total = max(len(facts), 1)
            scan.phase = f"analisando {len(facts)} achado(s)"
            scan.progress = 50
            await session.commit()

            created = 0
            for n, fact in enumerate(facts):
                if n % 20 == 0 and await _halted():
                    return {"halted": True}
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

                # 3b) Remediacao (NVD, cacheada localmente) para o CVE principal.
                assess_dict = assessment.to_dict()
                if cve_ids:
                    try:
                        rem = await get_remediation(session, cve_ids[0])
                    except Exception:  # noqa: BLE001  nunca derruba o scan
                        rem = None
                    if rem:
                        assess_dict["remediation"] = rem.get("solution")
                        assess_dict["references"] = rem.get("references") or []
                        if rem.get("description"):
                            assess_dict["cve_description"] = rem["description"]

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
                    existing.ai_assessment = {**(existing.ai_assessment or {}), **assess_dict}
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
                        ai_assessment=assess_dict,
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
                    # Screenshot (evidencia visual) -> data URI renderizavel.
                    shot = fact.data.get("screenshot_b64")
                    if shot:
                        session.add(Evidence(
                            finding_id=finding.id, kind="screenshot",
                            content="data:image/png;base64," + shot))
                    created += 1
                # analise ocupa de 50% a 95%
                if n % 5 == 0:
                    scan.progress = 50 + int(45 * (n + 1) / total)
                    scan.findings_count = created
                    scan.heartbeat = datetime.now(timezone.utc)
                    await session.commit()

            if await _halted():
                return {"halted": True}

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


async def update_cve_base(ctx: dict, full: bool = False) -> dict:
    """Atualiza a base local de CVE.
    full=True: baixa a base completa pela NVD (paginada + monitorada)."""
    from app.enrichment.cve_import import import_full_nvd, refresh_seen
    async with SessionLocal() as session:
        if full:
            return await import_full_nvd(session)
        return await refresh_seen(session)


async def scheduled_cve_update(ctx: dict) -> None:
    """Cron: le a config (DB) e roda a atualizacao quando vencer o intervalo.

    Como le do banco a cada ciclo, ligar/desligar e mudar o intervalo pelo
    painel tem efeito SEM reiniciar o worker.
    """
    from datetime import datetime, timezone

    from app.enrichment.cve_import import (
        get_schedule, import_full_nvd, refresh_seen,
    )
    async with SessionLocal() as session:
        cfg = await get_schedule(session)
        if not cfg.enabled:
            return
        now = datetime.now(timezone.utc)
        if cfg.last_run is not None:
            age_h = (now - cfg.last_run).total_seconds() / 3600
            if age_h < max(1, cfg.interval_hours):
                return
        # Venceu: roda conforme o modo escolhido.
        try:
            if cfg.full:
                res = await import_full_nvd(session)
                cfg.last_result = f"completa: {res.get('imported', 0)} CVEs"
            else:
                res = await refresh_seen(session)
                cfg.last_result = f"vistos: {res.get('updated', 0)} atualizados"
        except Exception as exc:  # noqa: BLE001
            cfg.last_result = f"erro: {exc}"
        cfg.last_run = datetime.now(timezone.utc)
        await session.commit()


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


def _cron_jobs():
    # Roda a cada 15 min; a propria task le a config no banco e decide se e hora
    # de atualizar. Fica SEMPRE registrado para a agenda do painel funcionar.
    from arq import cron
    return [cron(scheduled_cve_update, minute={0, 15, 30, 45}, run_at_startup=False)]


class WorkerSettings:
    functions = [run_scan, update_cve_base]
    cron_jobs = _cron_jobs()
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    on_startup = _startup
    max_jobs = 10
