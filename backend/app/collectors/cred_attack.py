"""Coletor de ATAQUE DE CREDENCIAIS (gated).

Spray de credenciais fracas/padrão contra serviços de login (web form, login
JSON, FTP, SSH). Anti-lockout e não-destrutivo (ver app.exploitation.credscan).
Só roda com autorização de exploração no engagement (gate no worker).
"""
from __future__ import annotations

from app.collectors.base import CollectedFact


class CredAttackCollector:
    name = "cred_attack"

    async def run(self, targets: list[str], ports: list[int] | None = None,
                  **kwargs) -> list[CollectedFact]:
        from app.exploitation.credscan import cred_attack_scan
        return await cred_attack_scan(
            targets,
            ports=ports,
            cancel_check=kwargs.get("cancel_check"),
            on_tick=kwargs.get("on_tick"),
            on_log=kwargs.get("on_log"),
            on_progress=kwargs.get("on_progress"),
            params=kwargs.get("params") or {},
        )
