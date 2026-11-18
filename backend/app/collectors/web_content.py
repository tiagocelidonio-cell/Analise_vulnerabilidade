"""Varredura de conteudo web (brute-force de caminhos/arquivos).

Procura caminhos e arquivos comuns que estejam VIVOS agora (/admin, /.git/,
/.env, /backup.sql, ...). Nao-destrutivo: apenas GET, sem seguir redirect,
com concorrencia limitada. Flag por status e por sensibilidade do caminho.
"""
from __future__ import annotations

import asyncio

from app.collectors.base import CollectedFact, host_only, http_fetch
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

        # Detecção de CATCH-ALL: apps SPA respondem 200 para QUALQUER caminho.
        # Sem isso, cada caminho da wordlist virava um falso achado. Medimos o
        # tamanho da resposta a um caminho aleatório por base.
        import secrets as _secrets
        catchall: dict[str, int | None] = {}

        async def _detect_catchall(base: str):
            lens = []
            for _ in range(2):
                res = await http_fetch(f"{base}/{_secrets.token_hex(12)}", timeout,
                                       max_body=4096, follow_redirects=False)
                if res and res[0] == 200:
                    lens.append(len(res[2] or ""))
                else:
                    catchall[base] = None
                    return
            catchall[base] = max(lens) if lens else None

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
            # Suprime falso-positivo de catch-all: 200 com tamanho ~ ao da
            # resposta genérica (e sem listagem) não é um caminho real.
            ca = catchall.get(base)
            if ca is not None and status == 200 and not listing:
                if abs(len(body_full) - ca) <= max(80, ca * 0.05):
                    return
            # 200 em caminho sensivel confirma exposicao; 401/403 indica existencia
            sev = hint if status == 200 else (
                "low" if hint in ("high", "medium") else "info"
            )
            clen = len(body_full or "")
            ctype = (_headers or {}).get("content-type", "")
            server = (_headers or {}).get("server", "")
            raw = (
                f"TESTE REALIZADO : requisição GET a caminho comum/sensível\n"
                f"REQUISIÇÃO      : GET {url}\n"
                f"RESPOSTA        : HTTP {status}"
                + (" (listagem de diretório!)" if listing else "") + "\n"
                f"CONTENT-TYPE    : {ctype or '-'}\n"
                f"TAMANHO         : {clen} bytes\n"
                + (f"SERVIDOR        : {server}\n" if server else "")
                + (f"TRECHO DA RESPOSTA:\n{body[:600]}\n" if body else "")
                + f"REPRODUZIR      : curl -s -i \"{url}\""
            )
            facts.append(
                CollectedFact(
                    target=base.split("//")[1], service="http",
                    title=f"[{status}] /{path}"
                          + (" (directory listing!)" if listing else ""),
                    raw=raw,
                    data={"severity_hint": "high" if listing else sev,
                          "url": url, "status": status, "content_type": ctype,
                          "size": clen, "listing": listing, "path": path,
                          "source": "web_content"},
                )
            )

        # Monta todos os probes (host x base x path) e roda em BLOCOS, com
        # cancelamento e heartbeat ENTRE blocos.
        probes = []
        bases = []
        for host in sorted({host_only(t) for t in targets if host_only(t)}):
            for base in _base_urls(host, ports):
                bases.append(base)
                for path, hint in _PATHS.items():
                    probes.append((base, path, hint))
        # Primeiro detecta catch-all em cada base (em paralelo).
        await asyncio.gather(*(_detect_catchall(b) for b in bases))
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
