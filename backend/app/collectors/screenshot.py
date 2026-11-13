"""Captura de tela (evidencia visual) de cada web host, estilo Pentest-Tools.

Usa o Chromium headless (instalado no Dockerfile) via subprocess matavel.
A imagem (PNG) vira uma evidencia 'screenshot' no achado, renderizada no painel.
Nao-intrusivo: apenas abre a pagina e fotografa.
"""
from __future__ import annotations

import asyncio
import base64
import os
import shutil
import tempfile

import httpx

from app.collectors.base import CollectedFact
from app.collectors.proc import run_killable

_HTTPS_PORTS = {443, 8443}
_MAX = 30  # teto de capturas por scan (evita payload gigante)


async def _responds(url: str) -> bool:
    """Checa rapido se ha servico web (evita screenshot de IP morto do range)."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=5,
                                     headers={"User-Agent": "VulnScope"}) as c:
            r = await c.get(url, follow_redirects=True)
            return r.status_code < 500
    except (httpx.HTTPError, OSError):
        return False


def _chromium() -> str | None:
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        p = shutil.which(name)
        if p:
            return p
    if os.path.exists("/opt/pw-browsers/chromium"):
        return "/opt/pw-browsers/chromium"
    return None


def _scheme(port: int) -> str:
    return "https" if port in _HTTPS_PORTS else "http"


class ScreenshotCollector:
    name = "screenshot"

    async def run(self, targets: list[str], ports: list[int] | None = None, **kwargs):
        chrome = _chromium()
        cancel_check = kwargs.get("cancel_check")
        on_tick = kwargs.get("on_tick")
        if chrome is None:
            return [CollectedFact(
                target=targets[0] if targets else "-", service="screenshot",
                title="Captura de tela indisponível (Chromium não instalado)",
                raw="Rebuild com o Dockerfile atualizado para habilitar screenshots.",
                data={"severity_hint": "info", "source": "screenshot_setup"})]

        plist = ports or [443, 80]
        hosts = [h.split("://")[-1].split("/")[0].split(":")[0] for h in targets]

        # 1) Descobre em PARALELO quais hosts tem web (evita travar num /24).
        sem = asyncio.Semaphore(50)

        async def first_alive(host: str) -> str | None:
            async with sem:
                for p in plist:
                    if await _responds(f"{_scheme(p)}://{host}:{p}"):
                        return f"{_scheme(p)}://{host}:{p}"
            return None

        alive = [u for u in await asyncio.gather(*(first_alive(h) for h in hosts)) if u]

        # 2) Captura (sequencial, chromium e pesado) ate o teto.
        facts: list[CollectedFact] = []
        count = 0
        for url in alive:
            if count >= _MAX:
                break
            host = url.split("://")[-1].split(":")[0]
            p = int(url.rsplit(":", 1)[-1])
            if cancel_check and await cancel_check():
                break
            if on_tick:
                try:
                    await on_tick(f"screenshot: {url}")
                except Exception:  # noqa: BLE001
                    pass
            tmp = tempfile.mktemp(suffix=".png")
            args = [chrome, "--headless", "--no-sandbox", "--disable-gpu",
                    "--hide-scrollbars", "--disable-dev-shm-usage",
                    "--virtual-time-budget=8000", "--window-size=1280,800",
                    f"--screenshot={tmp}", url]
            b64 = None
            try:
                await run_killable(args, cancel_check=cancel_check, on_tick=on_tick)
                if os.path.exists(tmp) and os.path.getsize(tmp) > 0:
                    with open(tmp, "rb") as fh:
                        b64 = base64.b64encode(fh.read()).decode("ascii")
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            if not b64:
                continue
            count += 1
            facts.append(CollectedFact(
                target=host, port=p, service="screenshot",
                title=f"Captura de tela: {url}",
                raw=url,
                data={"severity_hint": "info", "source": "screenshot",
                      "screenshot_b64": b64, "url": url}))
        return facts
