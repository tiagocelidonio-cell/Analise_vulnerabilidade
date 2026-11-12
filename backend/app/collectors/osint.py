"""OSINT: pegada publica da empresa — e-mails, domInios e IPs.

Fontes legitimas e nao-intrusivas:
- e-mails: extraidos das paginas publicas do dominio (home + paginas comuns)
  e, se configurado, da busca do Google (CSE).
- dominios/subdomInios: crt.sh (Certificate Transparency, API publica).
- IPs: resolucao DNS dos nomes encontrados.
Cada item vira um achado 'osint' (severidade info) para compor a superficie.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re

import httpx

from app.collectors.base import CollectedFact
from app.config import settings
from app.collectors.subdomain_enum import _resolve

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_COMMON_PAGES = ["", "contato", "contact", "sobre", "about", "fale-conosco",
                 "quem-somos", "privacidade", "privacy"]


def _is_domain(t: str) -> bool:
    try:
        ipaddress.ip_network(t, strict=False)
        return False
    except ValueError:
        return "." in t


async def _emails_from_site(client: httpx.AsyncClient, domain: str) -> set[str]:
    emails: set[str] = set()
    for scheme in ("https", "http"):
        for page in _COMMON_PAGES:
            url = f"{scheme}://{domain}/{page}".rstrip("/")
            try:
                r = await client.get(url, follow_redirects=True)
            except (httpx.HTTPError, OSError):
                continue
            for m in _EMAIL_RE.findall(r.text[:300000]):
                e = m.lower()
                if not e.endswith((".png", ".jpg", ".gif", ".svg", ".webp")):
                    emails.add(e)
        if emails:
            break
    return emails


async def _crtsh_domains(client: httpx.AsyncClient, domain: str) -> set[str]:
    try:
        r = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
        r.raise_for_status()
        rows = r.json()
    except (httpx.HTTPError, ValueError):
        return set()
    out: set[str] = set()
    for row in rows[:2000]:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain):
                out.add(name)
    return out


async def _google_emails(client: httpx.AsyncClient, domain: str) -> set[str]:
    if not settings.google_cse_enabled:
        return set()
    emails: set[str] = set()
    try:
        r = await client.get("https://www.googleapis.com/customsearch/v1", params={
            "key": settings.google_cse_key, "cx": settings.google_cse_cx,
            "q": f'"@{domain}"', "num": 10})
        if r.status_code < 400:
            for it in r.json().get("items", []):
                blob = f"{it.get('title','')} {it.get('snippet','')}"
                for m in _EMAIL_RE.findall(blob):
                    if m.lower().endswith("@" + domain):
                        emails.add(m.lower())
    except (httpx.HTTPError, ValueError):
        pass
    return emails


class OsintCollector:
    name = "osint"

    async def run(self, targets: list[str], **kwargs):
        on_tick = kwargs.get("on_tick")
        facts: list[CollectedFact] = []
        async with httpx.AsyncClient(verify=False, timeout=20,
                                     headers={"User-Agent": "Mozilla/5.0 VulnScope"}) as client:
            for raw in targets:
                domain = raw.split("://")[-1].split("/")[0].split(":")[0]
                if not _is_domain(domain):
                    continue

                async def tick(p):
                    if on_tick:
                        try:
                            await on_tick(p)
                        except Exception:  # noqa: BLE001
                            pass

                await tick(f"osint: e-mails de {domain}")
                emails = await _emails_from_site(client, domain)
                emails |= await _google_emails(client, domain)
                for e in sorted(emails):
                    facts.append(CollectedFact(
                        target=domain, service="osint",
                        title=f"E-mail público: {e}", raw=e,
                        data={"severity_hint": "info", "email": e, "source": "osint"}))

                await tick(f"osint: domínios (crt.sh) de {domain}")
                domains = await _crtsh_domains(client, domain)
                ips: set[str] = set()
                for d in sorted(domains):
                    resolved = await asyncio.to_thread(_resolve, d)
                    for ip in resolved:
                        ips.add(ip)
                    facts.append(CollectedFact(
                        target=d, service="osint",
                        title=f"Domínio público (CT): {d}", raw=", ".join(resolved) or "nao resolve",
                        data={"severity_hint": "info", "ips": resolved, "source": "osint_ct"}))

                facts.append(CollectedFact(
                    target=domain, service="osint",
                    title=f"Pegada pública de {domain}: {len(emails)} e-mails, "
                          f"{len(domains)} domínios, {len(ips)} IPs",
                    raw=f"emails={len(emails)} dominios={len(domains)} ips={len(ips)}",
                    data={"severity_hint": "info", "emails": sorted(emails),
                          "domains": sorted(domains), "ips": sorted(ips), "source": "osint_summary"}))
        return facts
