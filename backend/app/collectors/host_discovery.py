"""Etapa 1 do pipeline: descoberta de HOSTS ATIVOS no range.

Antes de varrer portas/web em 256 IPs (a maioria morta num /24), descobrimos
rapido QUEM esta vivo e so entao as etapas seguintes trabalham nesses hosts.
Isso corta o desperdicio que fazia o scan "travar" varrendo IPs mortos.

Tecnica: TCP connect leve em algumas portas comuns. Se conecta -> vivo (e ja
sabemos uma porta aberta). Se recusa a conexao (RST) -> o host existe, so a
porta esta fechada -> vivo. Timeout/sem rota -> considerado morto. Sem root,
sem ICMP: funciona no container do worker.
"""
from __future__ import annotations

import asyncio

from app.collectors.base import CollectedFact
from app.config import settings

# Portas de sondagem (espalhadas: web, SSH, RDP, SMB, DB, mail...).
_PROBE_PORTS = [80, 443, 22, 3389, 445, 139, 8080, 8443, 23, 21, 25, 3306]


async def _alive(host: str, timeout: float) -> tuple[bool, int]:
    """(vivo?, porta_aberta). porta 0 = vivo por RST (sem porta aberta aqui)."""
    for p in _PROBE_PORTS:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, p), timeout)
        except ConnectionRefusedError:
            return True, 0  # respondeu com RST -> host existe
        except (asyncio.TimeoutError, OSError):
            continue
        # Conectou -> vivo, porta aberta.
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True, p
    return False, 0


class HostDiscoveryCollector:
    name = "host_discovery"

    async def run(self, targets: list[str], ports: list[int] | None = None, **kwargs):
        cancel_check = kwargs.get("cancel_check")
        on_tick = kwargs.get("on_tick")
        timeout = min(settings.scan_connect_timeout, 1.5)
        conc = max(1, settings.scan_max_concurrency)
        sem = asyncio.Semaphore(conc)
        facts: list[CollectedFact] = []

        async def one(host: str) -> None:
            async with sem:
                up, port = await _alive(host, timeout)
            if up:
                facts.append(CollectedFact(
                    target=host, port=(port or None), service="host",
                    title=f"Host ativo: {host}",
                    raw=f"host up (via porta {port})" if port else "host up (RST)",
                    data={"severity_hint": "info", "alive": True,
                          "via_port": port, "source": "host_discovery"}))

        # Blocos: cancel/heartbeat ENTRE blocos (sessao async nao aceita commits
        # concorrentes vindos das corrotinas paralelas).
        chunk = max(conc, 64)
        for k in range(0, len(targets), chunk):
            if cancel_check is not None:
                try:
                    if await cancel_check():
                        break
                except Exception:  # noqa: BLE001
                    pass
            await asyncio.gather(*(one(h) for h in targets[k:k + chunk]))
            if on_tick is not None:
                try:
                    await on_tick()
                except Exception:  # noqa: BLE001
                    pass
        return facts
