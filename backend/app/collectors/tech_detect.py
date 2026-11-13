"""Fingerprint de tecnologias: mapeia a superficie de ataque de cada web host.

Detecta servidor, linguagem, framework/CMS, bibliotecas JS e pistas de SO a
partir de headers HTTP, cookies e do HTML. Nao-intrusivo (apenas GET).
Cada host vira um achado 'tech' listando o que foi identificado.
"""
from __future__ import annotations

import asyncio
import re

import httpx

from app.collectors.base import CollectedFact
from app.config import settings

_HTTP_PORTS = {80, 8000, 8080, 3000, 9000}
_HTTPS_PORTS = {443, 8443}

# Assinaturas no HTML/headers -> tecnologia.
_BODY_SIGNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"wp-content|wp-includes|/wp-json", re.I), "WordPress"),
    (re.compile(r"Drupal.settings|/sites/default/files", re.I), "Drupal"),
    (re.compile(r"Joomla|/media/jui/", re.I), "Joomla"),
    (re.compile(r"cdn\.shopify\.com|Shopify", re.I), "Shopify"),
    (re.compile(r"/_next/|__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version|angular", re.I), "Angular"),
    (re.compile(r"data-reactroot|react(?:-dom)?\.", re.I), "React"),
    (re.compile(r"vue(?:\.min)?\.js|data-v-", re.I), "Vue.js"),
    (re.compile(r"jquery[-.](\d+\.\d+[\.\d]*)", re.I), "jQuery {v}"),
    (re.compile(r"bootstrap[-.](\d+\.\d+[\.\d]*)", re.I), "Bootstrap {v}"),
    (re.compile(r"laravel", re.I), "Laravel"),
    (re.compile(r"csrf-token|rails", re.I), "Ruby on Rails"),
    (re.compile(r"Django|csrfmiddlewaretoken", re.I), "Django"),
]
_COOKIE_SIGNS = {
    "phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
    "aspsessionid": "ASP classico", "laravel_session": "Laravel",
    "ci_session": "CodeIgniter", "wordpress_": "WordPress", "connect.sid": "Node.js/Express",
}
_HEADER_SIGNS = {
    "x-powered-by": "{v}", "x-aspnet-version": "ASP.NET {v}",
    "x-generator": "{v}", "x-drupal-cache": "Drupal",
}


def _scheme(port: int) -> str:
    return "https" if port in _HTTPS_PORTS else "http"


def _os_hint(server: str) -> str | None:
    s = server.lower()
    if "win" in s or "iis" in s:
        return "Windows"
    if "ubuntu" in s:
        return "Linux (Ubuntu)"
    if "debian" in s:
        return "Linux (Debian)"
    if "centos" in s or "red hat" in s or "rhel" in s:
        return "Linux (RHEL/CentOS)"
    if "unix" in s or "nginx" in s or "apache" in s:
        return "Unix/Linux (provavel)"
    return None


async def _detect(client: httpx.AsyncClient, host: str, port: int) -> CollectedFact | None:
    url = f"{_scheme(port)}://{host}:{port}"
    try:
        r = await client.get(url, follow_redirects=True)
    except (httpx.HTTPError, OSError):
        return None
    tech: set[str] = set()
    headers = {k.lower(): v for k, v in r.headers.items()}

    server = headers.get("server", "")
    if server:
        tech.add(server)
        osh = _os_hint(server)
        if osh:
            tech.add(f"SO: {osh}")
    for h, tmpl in _HEADER_SIGNS.items():
        if h in headers:
            tech.add(tmpl.replace("{v}", headers[h]))
    cookies = headers.get("set-cookie", "").lower()
    for sign, name in _COOKIE_SIGNS.items():
        if sign in cookies:
            tech.add(name)
    body = r.text[:200000]
    for pat, name in _BODY_SIGNS:
        m = pat.search(body)
        if m:
            if "{v}" in name and m.groups():
                tech.add(name.replace("{v}", m.group(1)))
            else:
                tech.add(name.replace(" {v}", ""))
    mg = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if mg:
        tech.add(mg.group(1))

    # Sempre emite quando o host RESPONDEU (mesmo sem assinatura clara): ao menos
    # registra o servidor e o status, util para a superficie de ataque.
    if not tech:
        tech.add(f"servidor nao identificado (HTTP {r.status_code})")
    techs = sorted(tech)
    return CollectedFact(
        target=host, port=port, service="tech",
        title=f"Tecnologias em {host}: {', '.join(techs[:6])}{'…' if len(techs) > 6 else ''}",
        raw="\n".join(techs),
        data={"severity_hint": "info", "technologies": techs, "source": "tech_detect"},
    )


class TechDetectCollector:
    name = "tech_detect"

    async def run(self, targets: list[str], ports: list[int] | None = None, **kwargs):
        on_tick = kwargs.get("on_tick")
        plist = ports or [443, 80]
        # Timeout curto: num /24 a maioria dos IPs nao responde; nao da para
        # esperar muito por host (senao o scan "trava").
        timeout = min(settings.scan_connect_timeout * 2, 4.0)
        facts: list[CollectedFact] = []
        # on_tick (heartbeat) NAO pode ser chamado de dentro das corrotinas
        # paralelas: a sessao async do worker nao aceita commits concorrentes.
        # O worker ja bate o heartbeat a cada lote; aqui so sinalizamos no inicio.
        if on_tick:
            try:
                await on_tick()
            except Exception:  # noqa: BLE001
                pass
        sem = asyncio.Semaphore(40)  # roda os hosts em PARALELO
        async with httpx.AsyncClient(verify=False, timeout=timeout,
                                     headers={"User-Agent": "Mozilla/5.0 VulnScope"}) as client:
            async def one(raw_host: str) -> None:
                host = raw_host.split("://")[-1].split("/")[0].split(":")[0]
                async with sem:
                    for p in plist:
                        f = await _detect(client, host, p)
                        if f is not None:
                            facts.append(f)
                            break  # um fingerprint por host basta
            await asyncio.gather(*(one(h) for h in targets))
        return facts
