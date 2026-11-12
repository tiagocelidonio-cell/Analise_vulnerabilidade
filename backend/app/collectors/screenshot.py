"""Captura de tela (evidencia visual) de cada web host, estilo Pentest-Tools.

Usa o Chromium headless (instalado no Dockerfile) via subprocess matavel.
A imagem (PNG) vira uma evidencia 'screenshot' no achado, renderizada no painel.
Nao-intrusivo: apenas abre a pagina e fotografa.
"""
from __future__ import annotations

import base64
import os
import shutil
import tempfile

from app.collectors.base import CollectedFact
from app.collectors.proc import run_killable

_HTTPS_PORTS = {443, 8443}
_MAX = 30  # teto de capturas por scan (evita payload gigante)


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
        facts: list[CollectedFact] = []
        count = 0
        for raw_host in targets:
            host = raw_host.split("://")[-1].split("/")[0].split(":")[0]
            if count >= _MAX:
                break
            for p in plist:
                if count >= _MAX:
                    break
                url = f"{_scheme(p)}://{host}:{p}"
                tmp = tempfile.mktemp(suffix=".png")
                args = [chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
                        "--hide-scrollbars", "--disable-dev-shm-usage",
                        "--virtual-time-budget=8000", "--window-size=1280,800",
                        f"--screenshot={tmp}", url]
                try:
                    await run_killable(args, cancel_check=cancel_check, on_tick=on_tick)
                    if not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
                        continue
                    with open(tmp, "rb") as fh:
                        b64 = base64.b64encode(fh.read()).decode("ascii")
                finally:
                    with open(os.devnull, "w"):
                        try:
                            os.unlink(tmp)
                        except OSError:
                            pass
                count += 1
                facts.append(CollectedFact(
                    target=host, port=p, service="screenshot",
                    title=f"Captura de tela: {url}",
                    raw=url,
                    data={"severity_hint": "info", "source": "screenshot",
                          "screenshot_b64": b64, "url": url}))
                break  # uma captura por host
        return facts
