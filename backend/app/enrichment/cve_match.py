"""Correlacao banner -> produto/versao -> CVE (NVD).

Transforma um banner cru ("Server: nginx/1.18.0") em uma lista de CVEs
reais com CVSS. E o que da peso aos achados: sem isso, so temos "porta
aberta"; com isso, temos "porta aberta rodando software com CVE X".

Usa a API publica do NVD 2.0. Sem chave, respeita o limite de taxa
(5 req / 30s) com uma pequena espera. Degrada sem derrubar o pipeline.
"""
from __future__ import annotations

import asyncio
import re

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Padroes de banner -> (produto, versao). Ampliavel.
_BANNER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"OpenSSH[_/](\d+\.\d+[p\d]*)", re.I), "openssh"),
    (re.compile(r"nginx/(\d+\.\d+\.\d+)", re.I), "nginx"),
    (re.compile(r"Apache/(\d+\.\d+\.\d+)", re.I), "apache http server"),
    (re.compile(r"Microsoft-IIS/(\d+\.\d+)", re.I), "internet information services"),
    (re.compile(r"lighttpd/(\d+\.\d+\.\d+)", re.I), "lighttpd"),
    (re.compile(r"Exim\s+(\d+\.\d+)", re.I), "exim"),
    (re.compile(r"Postfix", re.I), "postfix"),
    (re.compile(r"ProFTPD\s+(\d+\.\d+\.\d+)", re.I), "proftpd"),
    (re.compile(r"vsftpd\s+(\d+\.\d+\.\d+)", re.I), "vsftpd"),
    (re.compile(r"MySQL[-/]?(\d+\.\d+\.\d+)", re.I), "mysql"),
    (re.compile(r"Redis.*?(\d+\.\d+\.\d+)", re.I | re.S), "redis"),
]


def parse_banner(banner: str) -> tuple[str, str | None] | None:
    """Extrai (produto, versao) de um banner. Versao pode ser None."""
    if not banner:
        return None
    for pattern, product in _BANNER_PATTERNS:
        m = pattern.search(banner)
        if m:
            version = m.group(1) if m.groups() else None
            return product, version
    return None


def _extract_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                return float(arr[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, ValueError, TypeError):
                continue
    return None


async def search_nvd(product: str, version: str | None, limit: int = 10) -> list[dict]:
    """Busca CVEs no NVD por palavra-chave produto+versao."""
    keyword = f"{product} {version}".strip() if version else product
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit,
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(NVD_URL, params=params)
            if resp.status_code == 403:
                # rate limit sem chave: espera e tenta uma vez
                await asyncio.sleep(6)
                resp = await client.get(NVD_URL, params=params)
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
    except (httpx.HTTPError, ValueError):
        return []

    out = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        out.append(
            {
                "cve_id": cve_id,
                "cvss": _extract_cvss(cve.get("metrics", {})),
                "description": desc[:300],
            }
        )
    return out


async def correlate(banner: str) -> dict:
    """Pipeline completo: banner -> produto/versao -> CVEs.

    Retorna {product, version, cve_ids, max_cvss, cves}. Vazio se nada casar.
    """
    parsed = parse_banner(banner)
    if parsed is None:
        return {"product": None, "version": None, "cve_ids": [], "max_cvss": None, "cves": []}

    product, version = parsed
    cves = await search_nvd(product, version)
    cve_ids = [c["cve_id"] for c in cves]
    cvss_values = [c["cvss"] for c in cves if c["cvss"] is not None]
    return {
        "product": product,
        "version": version,
        "cve_ids": cve_ids,
        "max_cvss": max(cvss_values, default=None),
        "cves": cves,
    }
