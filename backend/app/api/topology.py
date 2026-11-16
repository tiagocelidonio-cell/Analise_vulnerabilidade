"""Topologia do ambiente: grafo de nós (domínios, subdomínios, IPs, serviços)
colorido por risco. Alimenta a visualização (Cytoscape) e o relatório."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_engagement_access
from app.db import get_session
from app.models import Engagement, Finding

router = APIRouter(tags=["topology"])

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

    for f in findings:
        d = f.data or {}
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        tgt = f.target or ""
        ttype = "ip" if _is_ip(tgt) else ("subdomain" if (d.get("parent")) else "host")
        n = node(tgt, ttype, sev)
        if n:
            n["findings"] += 1

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
                edges.add((tgt, sid))

    node_ids = set(nodes.keys())
    edge_list = [{"source": s, "target": t} for (s, t) in edges
                 if s in node_ids and t in node_ids]
    return {"nodes": list(nodes.values()), "edges": edge_list}
