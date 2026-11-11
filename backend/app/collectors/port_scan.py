"""Port scanner assincrono em sockets puros — o "sem nmap".

Abre conexoes TCP com concorrencia limitada, faz banner grab e um probe
HTTP basico. Produz CollectedFact por porta aberta. Projetado para ser
responsavel: timeout curto e teto de concorrencia configuravel.
"""
from __future__ import annotations

import asyncio

from app.collectors.base import CollectedFact
from app.config import settings

# Portas comuns de infra + web + automacao/IoT (OT). Ajustavel por scan.
# OT/IoT: apenas conexao TCP (sem sondas), pois dispositivos industriais sao
# sensiveis. Detecta exposicao de protocolo, nao ataca.
DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
    8080, 8443, 9000, 9200, 11211, 27017,
    # --- Automacao / OT / IoT ---
    102, 502, 1883, 8883, 1911, 2404, 4840, 9600, 20000, 44818,  # ICS/OT
    554, 37777, 34567, 81, 8081,                                  # cameras/DVR/IoT
]

# Servicos de automacao/OT — exposicao destes a rede e achado serio.
OT_SERVICES = {
    "s7", "modbus", "mqtt", "mqtt-tls", "niagara-fox", "iec-104",
    "opc-ua", "omron-fins", "dnp3", "ethernet-ip", "bacnet",
}

_HTTP_PORTS = {80, 8000, 8080, 3000, 9000}
_HTTPS_PORTS = {443, 8443}

_SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
    9200: "elasticsearch", 27017: "mongodb",
    # Automacao / OT / IoT
    102: "s7", 502: "modbus", 1883: "mqtt", 8883: "mqtt-tls", 1911: "niagara-fox",
    2404: "iec-104", 4840: "opc-ua", 9600: "omron-fins", 20000: "dnp3",
    44818: "ethernet-ip", 554: "rtsp", 37777: "dahua-dvr", 34567: "dvr",
}


async def _probe_port(host: str, port: int, timeout: float) -> CollectedFact | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return None  # fechada/filtrada

    banner = ""
    try:
        if port in _HTTP_PORTS:
            writer.write(
                f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            )
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = data.decode("latin-1", "replace").strip()
        elif port not in _HTTPS_PORTS:
            # Muitos servicos (ssh, ftp, smtp) mandam banner ao conectar.
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            banner = data.decode("latin-1", "replace").strip()
    except (OSError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    service = _SERVICE_HINTS.get(port, "unknown")
    data = {"banner": banner}
    title = f"Porta {port}/tcp aberta ({service})"
    # Exposicao de protocolo de automacao/OT a rede e achado serio.
    if service in OT_SERVICES:
        data["severity_hint"] = "high"
        data["ot"] = True
        title = f"Protocolo de automacao/OT exposto: {service} ({port}/tcp)"
    return CollectedFact(
        target=host,
        port=port,
        service=service,
        title=title,
        raw=banner,
        data=data,
    )


class PortScanCollector:
    name = "port_scan"

    async def run(
        self,
        targets: list[str],
        ports: list[int] | None = None,
        **kwargs,
    ) -> list[CollectedFact]:
        ports = ports or DEFAULT_PORTS
        timeout = settings.scan_connect_timeout
        sem = asyncio.Semaphore(settings.scan_max_concurrency)

        async def guarded(host: str, port: int) -> CollectedFact | None:
            async with sem:
                return await _probe_port(host, port, timeout)

        tasks = [guarded(h, p) for h in targets for p in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
