"""Enumeracao de subdominios com subfinder (ProjectDiscovery).

subfinder consulta dezenas de fontes passivas -> acha MUITO mais subdominios
que o metodo proprio (crt.sh + wordlist). Resolve cada um para marcar os vivos.
Fallback: coletor Python (subdomain_enum) se subfinder nao estiver instalado.
"""
from __future__ import annotations

import asyncio
import ipaddress
import shutil

from app.collectors.base import CollectedFact
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
        if not shutil.which("subfinder"):
            from app.collectors.subdomain_enum import SubdomainEnumCollector
            return await SubdomainEnumCollector().run(targets)

        facts: list[CollectedFact] = []
        for domain in targets:
            if not _is_domain(domain):
                continue
            subs = await self._subfinder(domain)
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

            await asyncio.gather(*(resolve_one(h) for h in subs))
        return facts

    async def _subfinder(self, domain: str) -> list[str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-silent", "-all",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
        except OSError:
            return []
        return [ln.strip() for ln in out.decode("utf-8", "replace").splitlines() if ln.strip()]
