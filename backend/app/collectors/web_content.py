"""Varredura de conteudo web (brute-force de caminhos/arquivos).

Procura caminhos e arquivos comuns que estejam VIVOS agora (/admin, /.git/,
/.env, /backup.sql, ...). Nao-destrutivo: apenas GET, sem seguir redirect,
com concorrencia limitada. Flag por status e por sensibilidade do caminho.
"""
from __future__ import annotations

import asyncio

from app.collectors.base import CollectedFact, http_fetch
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
        cancel_check = kwargs.get("cancel_check")
        on_tick = kwargs.get("on_tick")
        ports = ports or sorted(_HTTP_PORTS | _HTTPS_PORTS)
        timeout = settings.scan_connect_timeout * 2
        conc = max(1, settings.scan_max_concurrency)
        sem = asyncio.Semaphore(conc)
        facts: list[CollectedFact] = []

        async def check(base: str, path: str, hint: str):
            url = f"{base}/{path}"
            async with sem:
                # follow_redirects=False: detecta o caminho, nao o destino do
                # redirect. Corpo limitado + teto de tempo (nao pendura).
                res = await http_fetch(url, timeout, max_body=2048,
                                       follow_redirects=False)
            if res is None:
                return
            status, _headers, body_full = res
            if status not in _INTERESTING:
                return
            body = body_full if status == 200 else ""
            listing = "Index of /" in body
            # 200 em caminho sensivel confirma exposicao; 401/403 indica existencia
            sev = hint if status == 200 else (
                "low" if hint in ("high", "medium") else "info"
            )
            facts.append(
                CollectedFact(
                    target=base.split("//")[1], service="http",
                    title=f"[{status}] /{path}"
                          + (" (directory listing!)" if listing else ""),
                    raw=f"{url}\nHTTP {status}"
                        + (f"\n{body[:300]}" if body else ""),
                    data={"severity_hint": "high" if listing else sev,
                          "url": url, "status": status,
                          "listing": listing, "path": path},
                )
            )

        # Monta todos os probes (host x base x path) e roda em BLOCOS, com
        # cancelamento e heartbeat ENTRE blocos.
        probes = []
        for host in targets:
            for base in _base_urls(host, ports):
                for path, hint in _PATHS.items():
                    probes.append((base, path, hint))
        chunk = max(conc, 64)
        for k in range(0, len(probes), chunk):
            if cancel_check is not None:
                try:
                    if await cancel_check():
                        break
                except Exception:  # noqa: BLE001
                    pass
            await asyncio.gather(*(check(b, p, h) for b, p, h in probes[k:k + chunk]))
            if on_tick is not None:
                try:
                    await on_tick()
                except Exception:  # noqa: BLE001
                    pass
        return facts
