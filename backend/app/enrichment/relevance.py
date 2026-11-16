"""Relevancia: cruza os CVEs recentes com as TECNOLOGIAS detectadas.

O diferencial do produto: "saiu um CVE critico para o Nginx/SAP que voce tem
no cliente X". Nao depende de internet nem de IA — usa a base local de CVE
(com produtos do CPE) e os achados de tecnologia dos ativos.

Casamento:
- FORTE (confianca "alta"): a palavra-chave da tecnologia aparece nos PRODUTOS
  do CVE (campo vindo do CPE). Preciso.
- FRACO (confianca "media"): aparece so na DESCRICAO do CVE. Mais abrangente,
  util para registros antigos sem CPE.
"""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.surface import _TECH_CATEGORIES
from app.enrichment.cve_import import _sev_from_cvss
from app.models import CveRemediation, Finding

# Vocabulario de termos de produto (deriva das categorias de tecnologia).
# Ordena do maior para o menor para casar o termo mais especifico primeiro.
_VOCAB = sorted(
    {kw for _, kws in _TECH_CATEGORIES for kw in kws},
    key=len, reverse=True,
)

# Termos genericos demais: so casam se vierem do CPE (produtos), nunca por
# descricao, para nao gerar falso-positivo (ex.: "linux" aparece em tudo).
_WEAK_ONLY_IN_PRODUCTS = {
    "linux", "windows", "unix", "java", "python", "node", "php", ".net",
    "ruby", "cdn", "react", "vue", "angular", "express", "spring", "oracle",
    "amazon", "google cloud", "gcp", "aws", "azure",
}


def tech_keywords(tech: str) -> set[str]:
    """Extrai as palavras-chave de produto de uma tecnologia detectada.

    Ex.: "nginx 1.18.0" -> {"nginx"}; "Apache Tomcat" -> {"apache", "tomcat"}.
    Se nada do vocabulario casar, usa o 1o token alfabetico (>=4 chars)."""
    t = tech.lower()
    out = {kw for kw in _VOCAB if kw in t}
    if not out:
        toks = re.findall(r"[a-z][a-z0-9.+-]{3,}", t)
        if toks:
            out.add(toks[0])
    return out


def _word_in(kw: str, text: str) -> bool:
    """Casa kw como termo inteiro (evita 'php' casar dentro de 'phpmyadmin'?
    nao — aqui queremos limite de palavra em ambos os lados)."""
    if not text:
        return False
    return re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text) is not None


def detected_tech_index(findings: list) -> dict[str, dict]:
    """kw -> {techs:set, hosts:set, engagements:set} a partir dos achados.

    Cada achado pode trazer engagement_id (para a visao de carteira)."""
    index: dict[str, dict] = {}
    for f in findings:
        techs = (f.data or {}).get("technologies") or []
        if not techs:
            continue
        host = f.target or ""
        eng = getattr(f, "engagement_id", None)
        for tech in techs:
            for kw in tech_keywords(tech):
                e = index.setdefault(kw, {"techs": set(), "hosts": set(),
                                          "engagements": set()})
                e["techs"].add(tech)
                if host:
                    e["hosts"].add(host)
                if eng:
                    e["engagements"].add(eng)
    return index


async def match_recent(
    session: AsyncSession,
    index: dict[str, dict],
    recent_limit: int = 500,
    out_limit: int = 80,
    eng_names: dict[str, str] | None = None,
) -> list[dict]:
    """Cruza o indice de tecnologias com os CVEs mais recentes da base."""
    if not index:
        return []
    rows = list(await session.scalars(
        select(CveRemediation)
        .where(CveRemediation.published.is_not(None))
        .order_by(CveRemediation.published.desc())
        .limit(min(recent_limit, 2000))))

    matches: list[dict] = []
    for r in rows:
        prod_text = " ".join(r.products or []).lower()
        desc = (r.description or "").lower()
        hit_kws: list[str] = []
        strong = False
        for kw, e in index.items():
            in_prod = _word_in(kw, prod_text)
            if in_prod:
                hit_kws.append(kw)
                strong = True
            elif kw not in _WEAK_ONLY_IN_PRODUCTS and _word_in(kw, desc):
                hit_kws.append(kw)
        if not hit_kws:
            continue
        techs: set[str] = set()
        hosts: set[str] = set()
        engs: set[str] = set()
        for kw in hit_kws:
            techs.update(index[kw]["techs"])
            hosts.update(index[kw]["hosts"])
            engs.update(index[kw]["engagements"])
        matches.append({
            "cve_id": r.cve_id,
            "cvss": r.cvss,
            "severity": _sev_from_cvss(r.cvss),
            "description": r.description,
            "published": r.published.isoformat() if r.published else None,
            "products": (r.products or [])[:8],
            "matched": sorted(set(hit_kws)),
            "technologies": sorted(techs)[:12],
            "hosts": sorted(h for h in hosts if h)[:20],
            "engagement_ids": sorted(engs),
            "clients": sorted({eng_names[e] for e in engs if eng_names and e in eng_names}),
            "confidence": "alta" if strong else "média",
        })

    # Ordena: forte primeiro, depois CVSS desc, depois mais recente.
    matches.sort(key=lambda m: (
        0 if m["confidence"] == "alta" else 1,
        -(m["cvss"] or 0),
        m["published"] or "",
    ))
    return matches[:out_limit]
