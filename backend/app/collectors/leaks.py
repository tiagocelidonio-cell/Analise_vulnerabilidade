"""Monitoramento de vazamentos (abordagem legitima — NAO e crawler de darkweb).

Verifica se e-mails/dominios da empresa aparecem em vazamentos conhecidos,
usando o Have I Been Pwned (HIBP) — base consolidada de breaches publicos.
Requer HIBP_API_KEY (a API de conta e paga). Sem chave, explica como ativar.

Alvos: e-mails diretos ou dominios (nesse caso coleta e-mails publicos do site).
Cada e-mail vazado vira um achado com a lista de breaches.
"""
from __future__ import annotations

import asyncio
import re

import httpx

from app.collectors.base import CollectedFact
from app.config import settings

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HIBP = "https://haveibeenpwned.com/api/v3/breachedaccount/"


async def _site_emails(client: httpx.AsyncClient, domain: str) -> set[str]:
    emails: set[str] = set()
    for page in ("", "contato", "contact", "sobre", "about"):
        url = f"https://{domain}/{page}".rstrip("/")
        try:
            r = await client.get(url, follow_redirects=True)
        except (httpx.HTTPError, OSError):
            continue
        for m in _EMAIL_RE.findall(r.text[:200000]):
            emails.add(m.lower())
    return emails


class LeaksCollector:
    name = "leaks"

    async def run(self, targets: list[str], **kwargs):
        on_tick = kwargs.get("on_tick")

        async def tick(p=None):
            if on_tick:
                try:
                    await on_tick(p)
                except Exception:  # noqa: BLE001
                    pass

        # Sem chave -> achado informativo explicando como habilitar.
        if not settings.hibp_api_key:
            return [CollectedFact(
                target=targets[0] if targets else "-", service="leaks",
                title="Monitoramento de vazamentos indisponível (configure HIBP_API_KEY)",
                raw="Defina HIBP_API_KEY no .env (chave da API do Have I Been Pwned) "
                    "para checar e-mails/domínios em vazamentos conhecidos.",
                data={"severity_hint": "info", "source": "leaks_setup"})]

        facts: list[CollectedFact] = []
        async with httpx.AsyncClient(
            timeout=20, headers={"hibp-api-key": settings.hibp_api_key,
                                 "User-Agent": "VulnScope"}) as client:
            # Monta a lista de e-mails a checar.
            emails: set[str] = set()
            async with httpx.AsyncClient(verify=False, timeout=20,
                                         headers={"User-Agent": "Mozilla/5.0 VulnScope"}) as web:
                for t in targets:
                    if "@" in t:
                        emails.add(t.lower())
                    elif "." in t:
                        await tick(f"leaks: coletando e-mails de {t}")
                        emails |= await _site_emails(web, t)

            for email in sorted(emails):
                await tick(f"leaks: {email}")
                try:
                    r = await client.get(
                        HIBP + email, params={"truncateResponse": "false"})
                except (httpx.HTTPError, OSError):
                    continue
                # HIBP: respeita o rate-limit (headers Retry-After); espaca.
                await asyncio.sleep(1.6)
                if r.status_code == 404:
                    continue  # sem vazamento conhecido
                if r.status_code == 401:
                    facts.append(CollectedFact(
                        target=email, service="leaks",
                        title="HIBP_API_KEY inválida ou sem assinatura ativa",
                        raw="A chave HIBP foi rejeitada (401).",
                        data={"severity_hint": "info", "source": "leaks_error"}))
                    break
                if r.status_code == 429:
                    await asyncio.sleep(3)
                    continue
                if r.status_code >= 400:
                    continue
                try:
                    breaches = r.json()
                except ValueError:
                    continue
                names = [b.get("Name") or b.get("Title") for b in breaches]
                has_pw = any(("Passwords" in (b.get("DataClasses") or [])) for b in breaches)
                facts.append(CollectedFact(
                    target=email, service="leaks",
                    title=f"E-mail em vazamento(s): {email} — {len(names)} breach(es)",
                    raw="Vazamentos: " + ", ".join(n for n in names if n),
                    data={"severity_hint": "high" if has_pw else "medium",
                          "breaches": names, "has_passwords": has_pw,
                          "source": "hibp"}))
        return facts
