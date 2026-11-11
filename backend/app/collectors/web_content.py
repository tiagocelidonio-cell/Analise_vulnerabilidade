"""Varredura de conteudo web (brute-force de caminhos/arquivos).

Procura caminhos e arquivos comuns que estejam VIVOS agora (/admin, /.git/,
/.env, /backup.sql, ...). Nao-destrutivo: apenas GET, sem seguir redirect,
com concorrencia limitada. Flag por status e por sensibilidade do caminho.
"""
from __future__ import annotations

import asyncio

import httpx

from app.collectors.base import CollectedFact
from app.config import settings

_HTTP_PORTS = {80, 8000, 8080, 3000, 9000}
_HTTPS_PORTS = {443, 8443}

# caminho -> dica de severidade se encontrado (status interessante)
_PATHS: dict[str, str] = {
    ".git/config": "high", ".git/HEAD": "high", ".env": "high",
    ".env.bak": "high", ".env.old": "high", "config.php.bak": "high",
    "backup.sql": "high", "backup.zip": "high", "dump.sql": "high",
    "db.sql": "high", "database.sql": "high", "id_rsa": "high",
    ".ssh/id_rsa": "high", "credentials.json": "high", "secrets.json": "high",
    ".htpasswd": "high", ".svn/entries": "high", "wp-config.php.bak": "high",
    ".aws/credentials": "high",
    "admin": "medium", "administrator": "medium", "wp-admin/": "medium",
    "phpmyadmin/": "medium", "adminer.php": "medium", "server-status": "medium",
    "actuator/env": "medium", "actuator/health": "low", "console": "medium",
    "jenkins/": "medium", "grafana/": "medium", "kibana/": "medium",
    "phpinfo.php": "medium", "info.php": "medium", "test.php": "low",
    ".DS_Store": "medium", "web.config": "medium", "backup/": "medium",
    "old/": "low", "dev/": "low", "staging/": "low", "uploads/": "low",
    "api/": "info", "api/v1/": "info", "swagger.json": "low",
    "swagger-ui/": "low", "robots.txt": "info", "sitemap.xml": "info",
    ".well-known/security.txt": "info", "composer.json": "low",
    "package.json": "low", ".vscode/settings.json": "medium",
}

# status que valem reportar
_INTERESTING = {200, 401, 403, 500}


def _base_urls(host: str, ports: list[int]) -> list[str]:
    urls = []
    for p in ports:
        if p in _HTTPS_PORTS:
            urls.append(f"https://{host}:{p}")
        elif p in _HTTP_PORTS:
            urls.append(f"http://{host}:{p}")
    return urls


class WebContentCollector:
    name = "web_content"

    async def run(
        self, targets: list[str], ports: list[int] | None = None, **kwargs
    ) -> list[CollectedFact]:
        ports = ports or sorted(_HTTP_PORTS | _HTTPS_PORTS)
        timeout = settings.scan_connect_timeout * 2
        sem = asyncio.Semaphore(settings.scan_max_concurrency)
        facts: list[CollectedFact] = []

        async def check(client: httpx.AsyncClient, base: str, path: str, hint: str):
            url = f"{base}/{path}"
            try:
                async with sem:
                    resp = await client.get(url)
            except (httpx.HTTPError, OSError):
                return
            if resp.status_code not in _INTERESTING:
                return
            body = resp.text[:2000] if resp.status_code == 200 else ""
            listing = "Index of /" in body
            # 200 em caminho sensivel confirma exposicao; 401/403 indica existencia
            sev = hint if resp.status_code == 200 else (
                "low" if hint in ("high", "medium") else "info"
            )
            facts.append(
                CollectedFact(
                    target=base.split("//")[1], service="http",
                    title=f"[{resp.status_code}] /{path}"
                          + (" (directory listing!)" if listing else ""),
                    raw=f"{url}\nHTTP {resp.status_code}"
                        + (f"\n{body[:300]}" if body else ""),
                    data={"severity_hint": "high" if listing else sev,
                          "url": url, "status": resp.status_code,
                          "listing": listing, "path": path},
                )
            )

        for host in targets:
            bases = _base_urls(host, ports)
            if not bases:
                continue
            async with httpx.AsyncClient(
                verify=False, timeout=timeout, follow_redirects=False
            ) as client:
                tasks = [
                    check(client, base, path, hint)
                    for base in bases
                    for path, hint in _PATHS.items()
                ]
                await asyncio.gather(*tasks)
        return facts
