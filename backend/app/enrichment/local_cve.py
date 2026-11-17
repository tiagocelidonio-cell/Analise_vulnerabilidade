"""Associacao de CVE por PRODUTO + VERSAO usando a BASE LOCAL (offline).

Faz o que faltava: usar os CVEs que voce baixou para associar aos achados do
scan, com precisao de VERSAO (faixas do CPE). Sem internet, sem nmap vulners.

Fluxo: achado traz (produto, versao) detectados (ex.: nmap -sV 'Apache httpd
2.4.49') -> mapeia para o produto CPE (apache:http_server) -> busca na base os
CVEs cujas regras CPE casam a versao -> anexa ao achado.
"""
from __future__ import annotations

import re

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CveRemediation

# Nome do servico/produto (nmap/banner) -> "vendor:product" do CPE.
_PRODUCT_CPE = {
    "apache tomcat": "apache:tomcat", "tomcat": "apache:tomcat",
    "apache httpd": "apache:http_server", "apache http server": "apache:http_server",
    "apache": "apache:http_server",
    "nginx": "nginx:nginx",
    "openssh": "openbsd:openssh",
    "lighttpd": "lighttpd:lighttpd",
    "microsoft iis httpd": "microsoft:internet_information_services",
    "internet information services": "microsoft:internet_information_services",
    "iis": "microsoft:internet_information_services",
    "mariadb": "mariadb:mariadb_server",
    "mysql": "oracle:mysql",
    "postgresql": "postgresql:postgresql", "postgres": "postgresql:postgresql",
    "openssl": "openssl:openssl",
    "php": "php:php",
    "exim": "exim:exim", "exim smtpd": "exim:exim",
    "postfix": "postfix:postfix",
    "vsftpd": "vsftpd:vsftpd", "proftpd": "proftpd:proftpd",
    "pure-ftpd": "pureftpd:pure-ftpd",
    "dovecot": "dovecot:dovecot",
    "samba": "samba:samba", "samba smbd": "samba:samba",
    "isc bind": "isc:bind", "bind": "isc:bind",
    "redis": "redis:redis", "mongodb": "mongodb:mongodb",
    "jenkins": "jenkins:jenkins", "grafana": "grafana:grafana",
    "node.js": "nodejs:node.js", "jetty": "eclipse:jetty",
    "wordpress": "wordpress:wordpress", "drupal": "drupal:drupal",
    "joomla": "joomla:joomla",
}


# "Produto/versao" ou "Produto versao" no banner/server (ex.: Apache/2.4.49).
_PV_RE = re.compile(r"([A-Za-z][A-Za-z0-9 ._+-]*?)[\s/_-]+v?(\d+\.\d[\w.\-]*)")


def extract_pv(data: dict, title: str = "") -> tuple[str | None, str | None]:
    """Extrai (produto, versao) de um achado, de VARIOS campos:
    product/version (nmap -sV), senao do Server header / banner / titulo."""
    data = data or {}
    p = (data.get("product") or "").strip()
    v = (data.get("version") or "").strip()
    if p:
        return p, (v or None)
    for src in (data.get("server"), data.get("banner"), title):
        if not src:
            continue
        m = _PV_RE.search(str(src))
        if m and product_to_cpe(m.group(1)):
            return m.group(1).strip(), m.group(2)
    # Produto SEM versao (ex.: Server: Apache; "(mysql)" no titulo).
    for src in (data.get("server"), data.get("banner"), title):
        if src and product_to_cpe(str(src)):
            return str(src), None
    return None, None


def product_to_cpe(name: str) -> str | None:
    """Mapeia o nome do produto detectado para o 'vendor:product' do CPE."""
    n = (name or "").strip().lower()
    if not n:
        return None
    if n in _PRODUCT_CPE:
        return _PRODUCT_CPE[n]
    # casa pela chave mais longa contida no nome (ex.: 'apache httpd 2.4' -> apache httpd)
    for k in sorted(_PRODUCT_CPE, key=len, reverse=True):
        if k in n:
            return _PRODUCT_CPE[k]
    return None


def _vtuple(v: str) -> tuple:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in nums[:5]) if nums else (0,)


def _rule_matches(version: str, rule: dict) -> bool:
    vt = _vtuple(version)
    exact = rule.get("ver") or ""
    if exact:
        return _vtuple(exact) == vt
    vs, ve = rule.get("vs") or "", rule.get("ve") or ""
    if not vs and not ve:
        # Sem faixa e sem versao exata -> afeta QUALQUER versao do produto.
        return True
    ok = True
    if vs:
        b = _vtuple(vs)
        ok = vt >= b if rule.get("vsi") else vt > b
    if ok and ve:
        b = _vtuple(ve)
        ok = vt <= b if rule.get("vei") else vt < b
    return ok


def _prod_token(cpe: str) -> str:
    """Token do PRODUTO (parte apos o ':'). O vendor varia na NVD (ex.: mysql
    aparece como 'oracle:mysql' e 'mysql:mysql'); casar pelo produto e' robusto."""
    return (cpe or "").split(":")[-1]


def _rule_prod_matches(rule: dict, token: str) -> bool:
    return _prod_token(rule.get("prod") or "") == token


# Palavras genericas que NAO servem de token de produto (ruido).
_NOISE_TOK = {"framework", "server", "httpd", "daemon", "service", "http",
              "https", "web", "app", "software", "the", "for", "and", "version",
              "httpd.", "ftp", "ftpd", "smtp", "smtpd", "ssh", "sshd", "api"}


# Hospedagem/CDN estatica: NAO e' software versionado -> nao ha CVE de versao
# para associar (ex.: owasp-juice.shop serve a landing no GitHub Pages).
_HOSTING = ("github.com", "cloudflare", "netlify", "vercel", "amazons3",
            "fastly", "akamai", "google frontend", "cloudfront", "pages.dev",
            "jekyll", "gitbook", "read the docs", "surge")


def is_hosting(product: str) -> bool:
    n = (product or "").lower()
    return any(h in n for h in _HOSTING)


def product_tokens(product: str) -> list[str]:
    """Tokens de PRODUTO CPE a tentar casar na base.

    1) Se o nome e' conhecido (mapa), usa o token do CPE. 2) Senao, deriva
    tokens do proprio nome e casa pelo produto na base. Hospedagem estatica
    (GitHub Pages, Netlify...) retorna [] -> nao e' software versionado."""
    if is_hosting(product):
        return []
    cpe = product_to_cpe(product)
    if cpe:
        return [_prod_token(cpe)]
    toks = re.findall(r"[a-z][a-z0-9.+_-]{2,}", (product or "").lower())
    seen, out = set(), []
    for t in toks:
        t = t.strip(".-_")
        if t and t not in _NOISE_TOK and t not in seen and len(t) >= 3:
            seen.add(t)
            out.append(t)
    return out[:4]


async def _candidates(session: AsyncSession, token: str) -> list:
    return list(await session.scalars(
        select(CveRemediation)
        .where(cast(CveRemediation.cpe, String).ilike(f"%{token}%"))
        .limit(5000)))


async def cves_for_service(session: AsyncSession, product: str, version: str,
                           limit: int = 25) -> list[dict]:
    """CVEs da BASE LOCAL que afetam (produto, versao). Vazio se nada casar."""
    if not version or _vtuple(version) == (0,):
        return []
    for token in product_tokens(product):
        rows = await _candidates(session, token)
        hits = []
        for r in rows:
            for rule in (r.cpe or []):
                if _rule_prod_matches(rule, token) and _rule_matches(version, rule):
                    hits.append(r)
                    break
        if hits:
            hits.sort(key=lambda r: -(r.cvss or 0))
            return [{"cve_id": r.cve_id, "cvss": r.cvss,
                     "description": r.description, "cpe": token} for r in hits[:limit]]
    return []


async def cves_for_product(session: AsyncSession, product: str,
                           limit: int = 12) -> list[dict]:
    """CVEs conhecidos do PRODUTO (sem versao) — os mais severos. POTENCIAIS."""
    for token in product_tokens(product):
        rows = await _candidates(session, token)
        hits = [r for r in rows
                if any(_rule_prod_matches(rule, token) for rule in (r.cpe or []))]
        if hits:
            hits.sort(key=lambda r: -(r.cvss or 0))
            return [{"cve_id": r.cve_id, "cvss": r.cvss, "description": r.description}
                    for r in hits[:limit]]
    return []
