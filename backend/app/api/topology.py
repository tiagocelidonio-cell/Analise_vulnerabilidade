"""Topologia do ambiente: grafo de nós (domínios, subdomínios, IPs, serviços)
colorido por risco. Alimenta a visualização (Cytoscape) e o relatório."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_engagement_access
from app.db import get_session
from app.models import Engagement, Finding

router = APIRouter(tags=["topology"])

_MAX_IMG = 6 * 1024 * 1024  # ~6 MB de data URI


class TopologyImage(BaseModel):
    image: str | None = None  # data URI PNG; None/"" limpa


@router.put("/engagements/{engagement_id}/topology-image")
async def save_topology_image(
    body: TopologyImage,
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Salva (ou limpa) a imagem da topologia capturada no painel, para embutir
    no relatório. Aceita apenas data URI PNG."""
    img = (body.image or "").strip()
    if img:
        if not img.startswith("data:image/png;base64,"):
            raise HTTPException(400, "Imagem deve ser um data URI PNG.")
        if len(img) > _MAX_IMG:
            raise HTTPException(413, "Imagem muito grande (máx. ~6 MB).")
        eng.topology_png = img
    else:
        eng.topology_png = None
    await session.commit()
    return {"saved": bool(img), "bytes": len(img)}

_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_MAX_NODES = 600


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


@router.get("/engagements/{engagement_id}/topology")
async def topology(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> dict:
    findings = list(await session.scalars(
        select(Finding).where(Finding.engagement_id == eng.id)))

    nodes: dict[str, dict] = {}
    edges: set[tuple] = set()

    def node(nid: str, ntype: str, sev: str | None = None):
        if not nid:
            return None
        n = nodes.get(nid)
        if n is None:
            if len(nodes) >= _MAX_NODES:
                return None
            n = {"id": nid, "label": nid, "type": ntype, "risk": "info", "findings": 0}
            nodes[nid] = n
        if sev and _RANK.get(sev, 1) > _RANK.get(n["risk"], 1):
            n["risk"] = sev
        return n

    # Escopo entra como nó base.
    for s in eng.scope or []:
        node(s, "ip" if _is_ip(s) else "domain")

    def add_item(n, f, sev, d):
        if n is None:
            return
        items = n.setdefault("items", [])
        if len(items) < 60:
            items.append({
                "title": f.title, "severity": sev,
                "cve_ids": (f.cve_ids or [])[:8], "cvss": f.cvss,
                "port": f.port, "service": f.service})
        techs = n.setdefault("techs", [])
        for t in d.get("technologies", []) or []:
            if t not in techs and len(techs) < 40:
                techs.append(t)

    for f in findings:
        d = f.data or {}
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        tgt = f.target or ""
        ttype = "ip" if _is_ip(tgt) else ("subdomain" if (d.get("parent")) else "host")
        n = node(tgt, ttype, sev)
        if n:
            n["findings"] += 1
            add_item(n, f, sev, d)

        # Camadas de proteção identificadas (DNS/WAF/e-mail) viram nós próprios,
        # ligados ao ativo, destacados como defesa (mérito da equipe).
        if d.get("kind") == "protection" and d.get("layers"):
            for k, v in (d["layers"] or {}).items():
                pid = f"🛡 {k}: {v}"[:70]
                pn = node(pid, "protection")
                if pn is not None:
                    pn["label"] = f"{k}: {v}"
                    pn["protection"] = True
                    edges.add((tgt, pid))

        parent = (d.get("parent") or "").lower()
        if parent:
            node(parent, "domain")
            edges.add((parent, tgt))
        for ip in d.get("ips", []) or []:
            node(ip, "ip")
            edges.add((tgt, ip))
        if f.port:
            sid = f"{tgt}:{f.port}"
            sn = node(sid, "service", sev)
            if sn:
                sn["label"] = f"{f.port}/{f.service or 'tcp'}"
                sn["findings"] = sn.get("findings", 0) + 1
                add_item(sn, f, sev, d)
                edges.add((tgt, sid))

    node_ids = set(nodes.keys())
    edge_list = [{"source": s, "target": t} for (s, t) in edges
                 if s in node_ids and t in node_ids]
    return {"nodes": list(nodes.values()), "edges": edge_list}
