"""Enumeracao de subdominios e DNS (estilo dnsenum), passivo + ativo.

Tecnicas:
- Passivo: Certificate Transparency (crt.sh) — subdominios de certs emitidos.
- Ativo: resolucao DNS de cada candidato + brute-force de nomes comuns.
- Registros DNS (A/AAAA/MX/NS/TXT/CNAME) do dominio.
- Tentativa de zone transfer (AXFR) — se permitido, e um achado grave.

Passivo nao toca o alvo (OSINT). O ativo so resolve nomes (consulta DNS),
nunca ataca. Gera CollectedFact por subdominio vivo e por achado de DNS.
"""
from __future__ import annotations

import asyncio

import httpx

from app.collectors.base import CollectedFact

CRTSH_URL = "https://crt.sh/"

# Lista enxuta de nomes comuns p/ brute-force. Ampliavel por wordlist externa.
_COMMON = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "cpanel", "whm",
    "ns1", "ns2", "dns", "vpn", "remote", "portal", "admin", "dev", "staging",
    "test", "hml", "homologacao", "api", "app", "m", "mobile", "blog", "shop",
    "loja", "cdn", "static", "assets", "img", "intranet", "git", "jenkins",
    "db", "sql", "mysql", "gateway", "gw", "proxy", "monitor", "grafana",
    "kibana", "jira", "confluence", "owa", "autodiscover", "sso", "auth",
]


def _dns_records(domain: str) -> dict:
    """Coleta registros DNS. Isolado para rodar em thread (dnspython e sync)."""
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 4
    out: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            ans = resolver.resolve(domain, rtype)
            out[rtype] = [r.to_text() for r in ans]
        except Exception:  # noqa: BLE001  (NXDOMAIN, NoAnswer, timeout...)
            continue
    return out


def _resolve(host: str) -> list[str] | None:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    try:
        ans = resolver.resolve(host, "A")
        return [r.to_text() for r in ans]
    except Exception:  # noqa: BLE001
        return None


def _try_axfr(domain: str) -> list[str]:
    """Tenta zone transfer em cada NS. Retorna nomes se algum permitir."""
    import dns.query
    import dns.resolver
    import dns.zone

    found: list[str] = []
    try:
        ns_list = [str(r) for r in dns.resolver.resolve(domain, "NS")]
    except Exception:  # noqa: BLE001
        return found
    for ns in ns_list:
        try:
            ns_ip = str(dns.resolver.resolve(ns, "A")[0])
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=6))
            found = [f"{n}.{domain}" for n in zone.nodes.keys()]
            if found:
                return found  # um NS vulneravel ja basta
        except Exception:  # noqa: BLE001
            continue
    return found


async def _crtsh(domain: str) -> set[str]:
    """Subdominios via Certificate Transparency (passivo)."""
    subs: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}
            )
            resp.raise_for_status()
            for row in resp.json():
                for name in str(row.get("name_value", "")).split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain):
                        subs.add(name)
    except (httpx.HTTPError, ValueError):
        pass
    return subs


class SubdomainEnumCollector:
    name = "subdomain_enum"

    async def run(
        self, targets: list[str], brute: bool = True, **kwargs
    ) -> list[CollectedFact]:
        facts: list[CollectedFact] = []
        for domain in targets:
            # 1) Registros DNS do dominio.
            records = await asyncio.to_thread(_dns_records, domain)
            if records:
                facts.append(
                    CollectedFact(
                        target=domain, service="dns",
                        title=f"Registros DNS de {domain}",
                        raw="\n".join(f"{k}: {', '.join(v)}" for k, v in records.items()),
                        data={"severity_hint": "info", "records": records},
                    )
                )

            # 2) Zone transfer (AXFR) — se permitido, e grave.
            axfr = await asyncio.to_thread(_try_axfr, domain)
            if axfr:
                facts.append(
                    CollectedFact(
                        target=domain, service="dns",
                        title=f"Zone transfer (AXFR) PERMITIDO em {domain}",
                        raw="Nomes expostos:\n" + "\n".join(sorted(axfr)[:200]),
                        data={"severity_hint": "high", "names": sorted(axfr)},
                    )
                )

            # 3) Candidatos: passivo (crt.sh) + brute-force.
            candidates = await _crtsh(domain)
            if brute:
                candidates |= {f"{w}.{domain}" for w in _COMMON}

            # 4) Resolve cada candidato (em paralelo, limitado).
            sem = asyncio.Semaphore(50)

            async def resolve_one(host: str) -> None:
                async with sem:
                    ips = await asyncio.to_thread(_resolve, host)
                if ips:
                    facts.append(
                        CollectedFact(
                            target=host, service="subdomain",
                            title=f"Subdominio vivo: {host}",
                            raw=f"A: {', '.join(ips)}",
                            data={"severity_hint": "low", "ips": ips,
                                  "parent": domain},
                        )
                    )

            await asyncio.gather(*(resolve_one(h) for h in sorted(candidates)))
        return facts
