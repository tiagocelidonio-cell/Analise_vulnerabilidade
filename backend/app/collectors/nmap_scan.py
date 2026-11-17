"""Port/host scan com nmap (ferramenta consagrada).

Vantagens sobre o scanner Python proprio:
- descobre hosts num range MESMO sem responder a ping (-Pn)
- deteccao de servico/versao (-sV) -> alimenta a correlacao CVE
- lida com ranges/CIDR nativamente, rapido e confiavel

Usa -sT (TCP connect), que NAO exige privilegios (roda no container sem root).
Se o nmap nao estiver instalado, cai no scanner Python (fallback).
"""
from __future__ import annotations

import re
import shutil
import xml.etree.ElementTree as ET

from app.collectors.base import CollectedFact
from app.collectors.port_scan import OT_SERVICES

# Extrai "CVE-2021-1234  7.5" (id + score) da saida do script vulners/vuln.
_CVE_SCORE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d+\.\d+)")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _cves_from_port(port_el) -> tuple[list[str], float | None]:
    """Le os <script> da porta (vulners/vuln) e extrai CVEs + maior CVSS.

    Herdado do tihacks: o nmap ja correlaciona servico->CVE localmente, sem
    depender de templates/internet do nuclei. Alimenta o mesmo pipeline de CVE.
    """
    cves: dict[str, float] = {}
    for script in port_el.findall(".//script"):
        sid = script.get("id", "")
        if "vulners" not in sid and "vuln" not in sid:
            continue
        output = script.get("output", "") or ""
        for cid, score in _CVE_SCORE_RE.findall(output):
            cves[cid] = max(cves.get(cid, 0.0), float(score))
        # CVEs sem score aparente tambem entram (score desconhecido)
        for cid in _CVE_RE.findall(output):
            cves.setdefault(cid, 0.0)
    if not cves:
        return [], None
    max_score = max(cves.values())
    return list(cves.keys()), (max_score or None)

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
            # CVEs detectados localmente pelo nmap (script vulners/vuln).
            cve_ids, max_cvss = _cves_from_port(port)
            if cve_ids:
                data["cve_ids"] = cve_ids
                if max_cvss:
                    data["cvss"] = max_cvss
                    data["severity_hint"] = _severity_from_score(max_cvss)
                else:
                    data.setdefault("severity_hint", "medium")
                vtxt = f" {version}" if version else ""
                title = (f"{len(cve_ids)} CVE(s) em {service}{vtxt} "
                         f"({portid}/tcp) — ex.: {cve_ids[0]}")
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

        # Perfil completo roda o script 'vulners' (CVE local, como no tihacks);
        # por isso ganha um host-timeout maior. Basico foca em portas/servicos.
        profile = kwargs.get("profile") or "full"
        full = profile != "basic"
        # Passos (checkbox na UI). None = segue o perfil (back-compat).
        steps = kwargs.get("steps")
        if steps is None:
            want_version, want_cve = True, full
        else:
            want_version = "port_scan:version" in steps
            want_cve = "port_scan:cve_local" in steps
        cancel_check = kwargs.get("cancel_check")
        on_tick = kwargs.get("on_tick")
        on_log = kwargs.get("on_log")
        from app.collectors.proc import run_killable

        port_sel = (["-p", ",".join(str(p) for p in ports)] if ports
                    else ["--top-ports", "1000"])

        # ===== FASE 1: descoberta RAPIDA de portas (sem -sV/scripts) =====
        # Sempre reporta as portas abertas, mesmo que a Fase 2 (lenta) estoure o
        # tempo. Antes era um comando so': se o -sV/script travava, o nmap
        # descartava o HOST INTEIRO -> "0 portas" num host que tinha portas.
        p1 = (["nmap", "-Pn", "-sT", "--open", "-T4", "--max-retries", "1",
               "--host-timeout", "60s", "-oX", "-"] + port_sel + list(targets))
        out1 = await run_killable(p1, cancel_check=cancel_check, on_tick=on_tick,
                                  max_seconds=180, on_log=on_log)
        facts = _parse_nmap_xml(out1) if out1 else []
        if not facts or not (want_version or want_cve):
            return facts  # so' portas (ou nada aberto)

        # ===== FASE 2: versao/CVE SO' nas portas abertas encontradas =====
        open_ports = sorted({f.port for f in facts if f.port})
        if not open_ports:
            return facts
        p2 = ["nmap", "-Pn", "-sT", "--open", "-T4", "--max-retries", "1",
              "--host-timeout", "180s", "-oX", "-",
              "-p", ",".join(str(p) for p in open_ports)]
        # So' DETECCAO DE VERSAO. Os CVEs NAO vem mais do nmap (vulners/vulscan):
        # a associacao e' feita pela BASE LOCAL (produto+versao) em persist_facts.
        if want_version or want_cve:
            p2 += ["-sV", "--version-intensity", "4"]  # mais preciso: so' nas abertas
        p2 += list(targets)
        out2 = await run_killable(p2, cancel_check=cancel_check, on_tick=on_tick,
                                  max_seconds=600, on_log=on_log)
        facts2 = _parse_nmap_xml(out2) if out2 else []

        # Merge: o enriquecido (Fase 2) substitui o basico (Fase 1) por host:porta.
        # Se a Fase 2 falhou/estourou, ficam as portas da Fase 1 (nunca "0").
        by_key = {(f.target, f.port): f for f in facts}
        for f in facts2:
            by_key[(f.target, f.port)] = f
        return list(by_key.values())
