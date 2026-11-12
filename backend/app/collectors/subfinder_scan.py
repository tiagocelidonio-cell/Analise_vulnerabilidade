"""Enumeracao de subdominios: subfinder + amass (passivo), combinados.

Herdado do sistema antigo (tihacks), que enumerava muito bem usando DUAS
fontes e deduplicando: subfinder (dezenas de fontes passivas) UNIAO amass
(passivo). Cada subdominio e resolvido (A) para marcar os vivos.

amass roda em modo PASSIVO (sem probing ativo -> rapido e sem risco de DoS) e
e opcional: se nao estiver instalado, segue so com o subfinder.
Fallback total: coletor Python (subdomain_enum) se nem subfinder existir.
"""
from __future__ import annotations

import asyncio
import ipaddress
import shutil
import time

from app.collectors.base import CollectedFact
from app.collectors.proc import run_killable
from app.collectors.subdomain_enum import _resolve


def _is_domain(t: str) -> bool:
    try:
        ipaddress.ip_network(t, strict=False)
        return False  # e IP/range
    except ValueError:
        return "." in t


class SubfinderCollector:
    name = "subdomain_enum"

    async def run(self, targets: list[str], **kwargs) -> list[CollectedFact]:
        cancel_check = kwargs.get("cancel_check")
        if not shutil.which("subfinder") and not shutil.which("amass"):
            from app.collectors.subdomain_enum import SubdomainEnumCollector
            return await SubdomainEnumCollector().run(targets)

        facts: list[CollectedFact] = []
        for domain in targets:
            if not _is_domain(domain):
                continue
            # Une as duas fontes e deduplica.
            found = set(await self._subfinder(domain, cancel_check))
            found |= set(await self._amass(domain, cancel_check))
            found.add(domain)
            sem = asyncio.Semaphore(50)

            async def resolve_one(host: str) -> None:
                async with sem:
                    ips = await asyncio.to_thread(_resolve, host)
                alive = bool(ips)
                facts.append(CollectedFact(
                    target=host, service="subdomain",
                    title=f"Subdominio {'vivo' if alive else 'encontrado'}: {host}",
                    raw=f"A: {', '.join(ips)}" if alive else "nao resolve (A)",
                    data={"severity_hint": "low" if alive else "info",
                          "ips": ips or [], "alive": alive, "parent": domain},
                ))

            await asyncio.gather(*(resolve_one(h) for h in found))
        return facts

    async def _subfinder(self, domain: str, cancel_check=None) -> list[str]:
        if not shutil.which("subfinder"):
            return []
        out = await run_killable(
            ["subfinder", "-d", domain, "-silent", "-all"],
            cancel_check=cancel_check)
        if not out:
            return []
        return [ln.strip() for ln in out.decode("utf-8", "replace").splitlines()
                if ln.strip()]

    async def _amass(self, domain: str, cancel_check=None) -> list[str]:
        """amass em modo passivo, com teto de ~3 min (interrompivel)."""
        if not shutil.which("amass"):
            return []
        deadline = time.monotonic() + 200

        async def stop() -> bool:
            if time.monotonic() > deadline:
                return True
            return bool(await cancel_check()) if cancel_check else False

        out = await run_killable(
            ["amass", "enum", "-passive", "-d", domain, "-silent", "-timeout", "3"],
            cancel_check=stop)
        if not out:
            return []
        dot_domain = domain.lower().lstrip(".")
        res = []
        for ln in out.decode("utf-8", "replace").splitlines():
            h = ln.strip().lower()
            # amass -silent as vezes imprime so o nome; mantem o que pertence ao dominio
            if h and (h == dot_domain or h.endswith("." + dot_domain)):
                res.append(h)
        return res
