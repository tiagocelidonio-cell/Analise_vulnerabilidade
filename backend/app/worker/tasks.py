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
from app.collectors import (
    COLLECTORS,
    DEFAULT_COLLECTORS,
    HOST_COLLECTORS,
    STAGE_LABELS,
    STAGE_ORDER,
    WEB_PORTS,
    WEB_STAGES,
)
from app.collectors.steps import collector_enabled_steps
from app.config import settings
from app.db import SessionLocal, init_db
from app.enrichment.cve_match import correlate
from app.enrichment.exploits import exploits_for_cve
from app.enrichment.remediation import get_remediation
from app.enrichment.sources import enrich_cves
from app.models import Evidence, Finding, ScanJob, ScanStatus, Severity
from app.scope import validate_targets
from app.targets import expand_targets


async def persist_facts(session, eng, scan, facts, exploit_cache, halted,
                        base_count: int = 0) -> tuple[int, bool]:
    """Enriquece, deduplica e GRAVA os fatos como Findings+Evidence.

    Chamada ao fim de CADA etapa -> os achados sobem para o banco
    incrementalmente (nao mais so no fim do scan). Retorna (criados, parou)."""
    created = 0
    total = max(len(facts), 1)
    for n, fact in enumerate(facts):
        if n % 20 == 0 and await halted():
            return created, True
        fact_dict = asdict(fact)
        now = datetime.now(timezone.utc)
        fdata = {k: v for k, v in (fact.data or {}).items()
                 if k != "screenshot_b64"}
        signature = f"{fact.target}|{fact.port}|{fact.title}".lower()

        # 1) CVEs: nuclei ja traz os CVEs; senao, correlaciona o banner (NVD).
        if fact.data.get("cve_ids"):
            cve_ids = fact.data["cve_ids"]
            correlation = {"cve_ids": cve_ids, "max_cvss": fact.data.get("cvss")}
        else:
            correlation = await correlate(fact.data.get("banner", "") or fact.raw)
            cve_ids = correlation["cve_ids"]
        fact_dict["correlation"] = correlation

        # 2) Enriquece com EPSS (probabilidade) e KEV (exploracao ativa).
        enrichment = await enrich_cves(cve_ids) if cve_ids else {
            "epss": {}, "kev": {}, "max_epss": 0.0, "any_kev": False}

        # 3) IA raciocina sobre os fatos ja provados.
        assessment = await analyst.assess(fact_dict, enrichment)
        assess_dict = assessment.to_dict()

        # 3b) Remediacao (NVD, cacheada) para o CVE principal.
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

        # 3c) Exploit publico conhecido (Exploit-DB) para o CVE principal.
        if cve_ids:
            cid = cve_ids[0]
            if cid not in exploit_cache:
                try:
                    exploit_cache[cid] = await exploits_for_cve(cid)
                except Exception:  # noqa: BLE001
                    exploit_cache[cid] = []
            if exploit_cache[cid]:
                fdata["exploits"] = exploit_cache[cid]
                assess_dict["exploit_available"] = True

        # Dedup: ja existe esse achado neste cliente? Entao so atualiza.
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
            if fdata:
                existing.data = {**(existing.data or {}), **fdata}
        else:
            finding = Finding(
                engagement_id=eng.id, scan_id=scan.id,
                target=fact.target, port=fact.port, service=fact.service,
                title=fact.title, description=assessment.risk_summary,
                severity=Severity(assessment.severity),
                cvss=correlation.get("max_cvss"),
                epss=enrichment.get("max_epss") or None,
                in_kev=enrichment.get("any_kev", False),
                cve_ids=cve_ids, data=fdata, ai_assessment=assess_dict,
                confidence=assessment.confidence, signature=signature,
                times_seen=1, last_seen=now,
            )
            session.add(finding)
            await session.flush()  # garante finding.id
            session.add(Evidence(
                finding_id=finding.id, kind="raw",
                content=fact.raw[:4000] if fact.raw else fact.title))
            shot = fact.data.get("screenshot_b64")
            if shot:
                session.add(Evidence(
                    finding_id=finding.id, kind="screenshot",
                    content="data:image/png;base64," + shot))
            created += 1
        if n % 5 == 0:
            scan.findings_count = base_count + created
            scan.heartbeat = datetime.now(timezone.utc)
            await session.commit()
    scan.findings_count = base_count + created
    await session.commit()
    return created, False


async def run_scan(ctx: dict, scan_id: str) -> dict:
    async with SessionLocal() as session:
        # Chaves de API do painel (Google CSE, HIBP, Claude) antes de coletar.
        from app.api.integrations import apply_db_keys
        await apply_db_keys(session)
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
            # É um RANGE (ex.: /24) quando a expansão gera mais IPs que alvos.
            is_range = len(host_targets) > len(scan.targets)

            # ===== PIPELINE POR ETAPAS =====
            # Monta o plano na ordem canônica a partir dos coletores escolhidos.
            # Cada etapa usa o resultado da anterior (hosts vivos -> portas ->
            # web) e GRAVA no banco ao terminar (achados sobem incrementalmente).
            # Falha de uma etapa é registrada e NÃO derruba o scan.
            chosen = list(selected)
            has_host_stage = any(c in HOST_COLLECTORS for c in chosen)
            if is_range and has_host_stage and "host_discovery" not in chosen:
                chosen = ["host_discovery"] + chosen  # etapa 1: poda IPs mortos
            stage_keys = [k for k in STAGE_ORDER if k in chosen]
            for k in chosen:  # selecionados fora da ordem canônica
                if k not in stage_keys and k in COLLECTORS:
                    stage_keys.append(k)
            nstages = max(len(stage_keys), 1)

            # Sub-passos selecionados (checkbox na UI). Vazio = roda tudo.
            sel_steps = set(scan.substeps or []) or None

            stage_log: list[dict] = []      # status por etapa -> scan.stages
            live_hosts: set | None = None   # setado pela descoberta de hosts
            web_hosts: set | None = None    # setado pelo port_scan (hosts c/ web)
            created_total = 0
            _exploit_cache: dict[str, list] = {}
            counters = {"subdomain": 0, "ports": 0, "web": 0, "ot": 0, "hosts": 0}

            def _stage_targets(nm: str) -> list[str]:
                if nm not in HOST_COLLECTORS:
                    return scan.targets                       # recon de domínio
                if nm in WEB_STAGES:
                    if web_hosts is not None:
                        return sorted(web_hosts)              # só hosts com web
                    if live_hosts is not None:
                        return sorted(live_hosts)
                    return host_targets
                if nm == "port_scan" and live_hosts is not None:
                    return sorted(live_hosts)                 # só hosts vivos
                return host_targets

            for i, name in enumerate(stage_keys):
                if await _halted():
                    return {"halted": True}
                label = STAGE_LABELS.get(name, name)
                entry = {"key": name, "label": label, "status": "running",
                         "found": 0, "created": 0, "error": None}
                stage_log.append(entry)
                base = 5 + int(85 * i / nstages)
                scan.phase = f"Etapa {i + 1}/{nstages}: {label}"
                scan.progress = base
                scan.stages = list(stage_log)
                scan.heartbeat = datetime.now(timezone.utc)
                await session.commit()

                collector = COLLECTORS.get(name)
                tlist = _stage_targets(name)
                if collector is None:
                    entry["status"] = "skipped"
                    entry["error"] = "coletor indisponível"
                    scan.stages = list(stage_log)
                    await session.commit()
                    continue
                if not tlist:
                    entry["status"] = "skipped"
                    entry["error"] = "sem alvos (etapa anterior não achou hosts)"
                    scan.stages = list(stage_log)
                    await session.commit()
                    continue

                # Host collectors em LOTES (cancelar/heartbeat/matar processo no
                # meio). Falha de UMA etapa é registrada e o scan segue.
                steps = collector_enabled_steps(name, sel_steps)
                facts: list = []
                try:
                    if name in HOST_COLLECTORS and len(tlist) > 16:
                        for j in range(0, len(tlist), 16):
                            if await _halted():
                                return {"halted": True}
                            batch = tlist[j:j + 16]
                            facts.extend(await collector.run(
                                batch, ports=scan.ports or None, profile=prof,
                                cancel_check=_abort_check, on_tick=_beat,
                                steps=steps))
                            frac = (j + len(batch)) / len(tlist)
                            scan.phase = (f"Etapa {i + 1}/{nstages}: {label} "
                                          f"({int(frac * 100)}%)")
                            scan.heartbeat = datetime.now(timezone.utc)
                            await session.commit()
                    else:
                        facts = await collector.run(
                            tlist, ports=scan.ports or None, profile=prof,
                            cancel_check=_abort_check, on_tick=_beat, steps=steps)
                except Exception as exc:  # noqa: BLE001  etapa falha, scan segue
                    entry["status"] = "failed"
                    entry["error"] = str(exc)[:300]
                    scan.stages = list(stage_log)
                    scan.heartbeat = datetime.now(timezone.utc)
                    await session.commit()
                    continue

                # Feed-forward: resultado desta etapa alimenta as próximas.
                if name == "host_discovery":
                    live_hosts = {f.target for f in facts if f.service == "host"}
                    counters["hosts"] += len(live_hosts)
                if name == "port_scan":
                    web_hosts = {f.target for f in facts
                                 if f.port in WEB_PORTS
                                 and "aberta" in (f.title or "").lower()}
                counters["subdomain"] += sum(1 for f in facts if f.service == "subdomain")
                counters["ports"] += sum(1 for f in facts if "aberta" in (f.title or "").lower())
                counters["web"] += sum(1 for f in facts if f.service in ("http", "https"))
                counters["ot"] += sum(1 for f in facts if (f.data or {}).get("ot"))

                # GRAVA os achados desta etapa AGORA (sobem para o banco).
                if facts:
                    scan.phase = (f"Etapa {i + 1}/{nstages}: {label} — "
                                  f"gravando {len(facts)} achado(s)")
                    await session.commit()
                delta, was_halted = await persist_facts(
                    session, eng, scan, facts, _exploit_cache, _halted,
                    base_count=created_total)
                if was_halted:
                    return {"halted": True}
                created_total += delta
                entry["found"] = len(facts)
                entry["created"] = delta
                entry["status"] = "ok"
                scan.stages = list(stage_log)
                scan.progress = 5 + int(85 * (i + 1) / nstages)
                scan.findings_count = created_total
                scan.heartbeat = datetime.now(timezone.utc)
                await session.commit()

            created = created_total
            if await _halted():
                return {"halted": True}

            # Resumo amigável do que foi encontrado + falhas por etapa.
            parts = []
            if counters["subdomain"]:
                parts.append(f"{counters['subdomain']} subdomínios")
            if counters["hosts"]:
                parts.append(f"{counters['hosts']} hosts ativos")
            if counters["ports"]:
                parts.append(f"{counters['ports']} portas abertas")
            if counters["web"]:
                parts.append(f"{counters['web']} serviços web")
            if counters["ot"]:
                parts.append(f"{counters['ot']} OT/IoT")
            failed = [e["label"] for e in stage_log if e["status"] == "failed"]
            scan.summary = ", ".join(parts) or f"{created} achados"
            if failed:
                scan.summary += f" · falhas: {', '.join(failed)}"

            scan.status = ScanStatus.completed
            scan.phase = ("concluído com falhas em " + ", ".join(failed)
                          if failed else "concluído")
            scan.progress = 100
            scan.findings_count = created
            scan.finished_at = datetime.now(timezone.utc)
            await session.commit()

            # Recon recursivo (nivel 1): so em scan SEMENTE (auto_level 0) com
            # auto_recon ligado. Enfileira UMA varredura dos subdominios vivos
            # descobertos (no escopo, ainda nao escaneados). Sem recursao alem.
            if getattr(eng, "auto_recon", False) and (scan.auto_level or 0) == 0:
                try:
                    await _auto_recon(ctx, session, eng, scan)
                except Exception:  # noqa: BLE001  nunca derruba o scan
                    pass
            return {"findings": created}

        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.failed
            scan.error = str(exc)
            await session.commit()
            return {"error": str(exc)}


async def _auto_recon(ctx, session, eng, scan) -> None:
    """Nivel 1: varre automaticamente os subdominios vivos descobertos (no
    escopo), que ainda nao foram alvo de uma varredura de portas. Teto de 200.
    So subdominios (nunca IPs resolvidos). Nao recorre alem do nivel 1."""
    from app.scope import is_in_scope

    scope = eng.scope or []
    # Subdominios vivos no escopo.
    subs: set[str] = set()
    rows = await session.scalars(
        select(Finding).where(
            Finding.engagement_id == eng.id, Finding.service == "subdomain"))
    for f in rows:
        d = f.data or {}
        host = (f.target or "").lower()
        if host and d.get("alive") and is_in_scope(host, scope):
            subs.add(host)
    if not subs:
        return
    # Dedup: remove os que ja foram alvo de alguma varredura de portas.
    scanned: set[str] = set()
    srows = await session.scalars(
        select(ScanJob).where(ScanJob.engagement_id == eng.id))
    for s in srows:
        if "port_scan" in (s.collectors or []):
            for t in s.targets or []:
                scanned.add((t or "").lower())
    todo = sorted(subs - scanned)[:200]
    if not todo:
        return
    new = ScanJob(
        engagement_id=eng.id, targets=todo,
        collectors=["port_scan", "http_probe", "tech_detect"],
        profile="full", status=ScanStatus.queued, auto_level=1,
    )
    session.add(new)
    await session.commit()
    await session.refresh(new)
    try:
        await ctx["redis"].enqueue_job("run_scan", new.id)
    except Exception:  # noqa: BLE001  se nao conseguir enfileirar, fica na fila
        pass


async def update_cve_base(ctx: dict, full: bool = False, resume: bool = False) -> dict:
    """Atualiza a base local de CVE.
    full=True: baixa a base completa pela NVD (paginada + monitorada).
    resume=True: retoma o download completo de onde parou (apos reinicio)."""
    from app.api.integrations import apply_db_keys
    from app.enrichment.cve_import import import_full_nvd, refresh_seen
    async with SessionLocal() as session:
        await apply_db_keys(session)  # pega NVD_API_KEY salva no painel
        if full:
            return await import_full_nvd(session, resume=resume)
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

    # Download de CVE orfao: o worker caiu/reiniciou no meio (ex.: um
    # `docker compose up -d --build`). O status fica preso em "baixando" sem
    # ninguem para avanca-lo nem ler o cancelamento. RETOMA de onde parou.
    from app.enrichment.cve_import import get_import_status
    resume_cve = False
    async with SessionLocal() as session:
        st = await get_import_status(session)
        if st.state in ("connecting", "downloading"):
            st.phase = "retomando após reinício…"
            st.cancel_requested = False
            st.updated_at = datetime.now(timezone.utc)
            await session.commit()
            resume_cve = True
    if resume_cve:
        try:
            redis = ctx.get("redis")
            if redis is None:
                from arq import create_pool
                redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
            # update_cve_base(ctx, full=True, resume=True)
            await redis.enqueue_job("update_cve_base", True, True)
        except Exception:  # noqa: BLE001  se nao enfileirar, a UI permite forcar
            pass


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
