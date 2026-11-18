"""Coletor de MAPEAMENTO DE CONTEÚDO web (descoberta de superfície).

Lê robots.txt/sitemap, rastreia e faz força-bruta de caminhos comuns para achar
páginas de login, APIs, diretórios e arquivos sensíveis. Não-destrutivo (GET),
recon — não exige autorização de exploração. Ver app.exploitation.contentscan.
"""
from __future__ import annotations

from app.collectors.base import CollectedFact


class ContentDiscoveryCollector:
    name = "content_discovery"

    async def run(self, targets: list[str], ports: list[int] | None = None,
                  **kwargs) -> list[CollectedFact]:
        from app.exploitation.contentscan import content_discovery_scan
        return await content_discovery_scan(
            targets,
            ports=ports,
            cancel_check=kwargs.get("cancel_check"),
            on_tick=kwargs.get("on_tick"),
            on_log=kwargs.get("on_log"),
        )
