"""Port/host scan com nmap (ferramenta consagrada).

Vantagens sobre o scanner Python proprio:
- descobre hosts num range MESMO sem responder a ping (-Pn)
- deteccao de servico/versao (-sV) -> alimenta a correlacao CVE
- lida com ranges/CIDR nativamente, rapido e confiavel

Usa -sT (TCP connect), que NAO exige privilegios (roda no container sem root).
Se o nmap nao estiver instalado, cai no scanner Python (fallback).
"""
from __future__ import annotations

import asyncio
import shutil
import xml.etree.ElementTree as ET

from app.collectors.base import CollectedFact
from app.collectors.port_scan import OT_SERVICES

_OT_PORT_NAMES = {
    502: "modbus", 102: "s7", 1883: "mqtt", 8883: "mqtt-tls", 2404: "iec-104",
    4840: "opc-ua", 20000: "dnp3", 44818: "ethernet-ip", 1911: "niagara-fox",
}


def _parse_nmap_xml(xml_bytes: bytes) -> list[CollectedFact]:
    facts: list[CollectedFact] = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return facts
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid"))
            svc_el = port.find("service")
            service = svc_el.get("name") if svc_el is not None else "unknown"
            product = (svc_el.get("product", "") if svc_el is not None else "")
            version = (svc_el.get("version", "") if svc_el is not None else "")
            banner = f"{product} {version}".strip() or f"{service}"
            # normaliza OT pelo numero da porta (nmap nem sempre nomeia OT)
            if portid in _OT_PORT_NAMES:
                service = _OT_PORT_NAMES[portid]
            data = {"banner": banner, "product": product, "version": version}
            title = f"Porta {portid}/tcp aberta ({service}{' ' + version if version else ''})"
            if service in OT_SERVICES:
                data["severity_hint"] = "high"
                data["ot"] = True
                title = f"Protocolo de automacao/OT exposto: {service} ({portid}/tcp)"
            facts.append(CollectedFact(
                target=ip, port=portid, service=service, title=title,
                raw=banner, data=data,
            ))
    return facts


class NmapCollector:
    name = "port_scan"

    async def run(self, targets: list[str], ports: list[int] | None = None, **kwargs):
        if not shutil.which("nmap"):
            # Fallback: scanner Python (expande o range manualmente).
            from app.collectors.port_scan import PortScanCollector
            from app.targets import expand_targets
            return await PortScanCollector().run(expand_targets(targets), ports=ports)

        # -sV com limites para nao travar em hosts que nao respondem direito.
        # --host-timeout curto mantem o lote agil e o "Parar" responsivo.
        args = ["nmap", "-Pn", "-sT", "-sV", "--version-intensity", "2",
                "--open", "-T4", "--max-retries", "1", "--host-timeout", "45s",
                "-oX", "-"]
        if ports:
            args += ["-p", ",".join(str(p) for p in ports)]
        else:
            args += ["--top-ports", "200"]
        args += list(targets)  # nmap expande CIDR/range nativamente

        try:
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
        except OSError:
            return []
        return _parse_nmap_xml(out)
