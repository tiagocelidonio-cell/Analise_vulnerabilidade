"""Superficie de ataque consolidada + mapa de tecnologias (estilo dos slides).

Agrega os achados do engagement: dominios, subdominios, IPs, servicos, e-mails
e as tecnologias detectadas, categorizadas. Alimenta um painel e o relatorio.
"""
from __future__ import annotations

import ipaddress
import re

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_engagement_access
from app.db import get_session
from app.models import Engagement, Finding

router = APIRouter(tags=["surface"])

# Categoria -> palavras-chave (minusculas) para classificar tecnologias.
_TECH_CATEGORIES = [
    ("Infraestrutura em Nuvem", ["google cloud", "gcp", "amazon", "aws", "azure",
                                 "cloudflare", "akamai", "fastly", "firebase", "cdn"]),
    ("Servidores Web", ["nginx", "apache", "iis", "litespeed", "caddy", "openresty", "tomcat"]),
    ("Sistema Corporativo", ["sap", "oracle ebs", "salesforce", "sharepoint", "dynamics"]),
    ("CMS / Framework", ["wordpress", "drupal", "joomla", "laravel", "django",
                         "rails", "next.js", "react", "vue", "angular", "shopify",
                         "spring", "codeigniter", "express"]),
    ("Banco de Dados", ["mysql", "mariadb", "postgres", "mongodb", "redis", "mssql", "oracle"]),
    ("Linguagem", ["php", "java", "python", "node", "asp.net", "ruby", ".net", "golang"]),
    ("Sistema Operacional", ["windows", "linux", "ubuntu", "debian", "centos",
                             "red hat", "rhel", "freebsd", "openbsd", "unix"]),
]


def _categorize(tech: str) -> str:
    t = tech.lower()
    for cat, kws in _TECH_CATEGORIES:
        if any(k in t for k in kws):
            return cat
    return "Outras"


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


@router.get("/engagements/{engagement_id}/surface")
async def surface(
    eng: Engagement = Depends(require_engagement_access),
    session: AsyncSession = Depends(get_session),
) -> dict:
    findings = list(await session.scalars(
        select(Finding).where(Finding.engagement_id == eng.id)))

    domains: set[str] = set()
    subdomains: set[str] = set()
    ips: set[str] = set()
    web: set[str] = set()
    services: set[tuple] = set()
    emails: set[str] = set()
    tech_hosts: dict[str, set[str]] = {}  # tech -> hosts

    for f in eng.scope or []:
        if _is_ip(f):
            ips.add(f)
        elif "." in f:
            domains.add(f.lower())

    for f in findings:
        d = f.data or {}
        svc = (f.service or "").lower()
        tgt = f.target or ""
        if svc == "subdomain":
            subdomains.add(tgt.lower())
            parent = (d.get("parent") or "").lower()
            if parent:
                domains.add(parent)
            for ip in d.get("ips", []) or []:
                ips.add(ip)
        if svc in ("http", "https"):
            web.add(tgt)
        if f.port:
            services.add((tgt, f.port))
        if _is_ip(tgt):
            ips.add(tgt)
        for ip in d.get("ips", []) or []:
            ips.add(ip)
        if d.get("email"):
            emails.add(d["email"])
        for e in d.get("emails", []) or []:
            emails.add(e)
        for t in d.get("technologies", []) or []:
            tech_hosts.setdefault(t, set()).add(tgt)

    # Monta o mapa de tecnologias por categoria.
    cats: dict[str, dict] = {}
    for tech, hosts in tech_hosts.items():
        cat = _categorize(tech)
        c = cats.setdefault(cat, {"category": cat, "items": {}})
        c["items"].setdefault(tech, set()).update(hosts)
    tech_map = []
    for cat in cats.values():
        items = [{"tech": t, "hosts": sorted(h)[:20], "count": len(h)}
                 for t, h in sorted(cat["items"].items(), key=lambda x: -len(x[1]))]
        tech_map.append({"category": cat["category"], "items": items})
    tech_map.sort(key=lambda c: c["category"])

    return {
        "counts": {
            "domains": len(domains), "subdomains": len(subdomains),
            "ips": len(ips), "web_services": len(web),
            "services": len(services), "emails": len(emails),
        },
        "domains": sorted(domains)[:200],
        "subdomains": sorted(subdomains)[:500],
        "ips": sorted(ips)[:500],
        "emails": sorted(emails)[:200],
        "tech_map": tech_map,
    }
