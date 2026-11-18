"""Coletor de REDE e PROTEÇÕES (passivo): DNS, hospedagem, provedor de DNS,
CDN/WAF e segurança de e-mail — associado ao cliente.

Produz achados que alimentam a topologia e o relatório. As CAMADAS DE PROTEÇÃO
(WAF/CDN, gateway de e-mail, DMARC/SPF/DNSSEC/CAA) são registradas como mérito da
equipe de segurança e para orientar o pentest. Informação pública, não-intrusivo.
"""
from __future__ import annotations

import ipaddress

from app.collectors.base import CollectedFact


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _facts(domain: str, r: dict) -> list[CollectedFact]:
    out: list[CollectedFact] = []
    recs = r.get("records", {})

    # 1) DNS + hospedagem (informativo; vira FATO do ambiente).
    techs = list(r.get("hosting", [])) + list(r.get("dns_provider", []))
    summary = []
    for k in ("A", "AAAA", "MX", "NS", "CNAME"):
        if recs.get(k):
            summary.append(f"{k}: {', '.join(recs[k][:5])}")
    raw = "\n".join([
        f"Domínio: {domain}",
        "Hospedagem: " + (", ".join(r.get("hosting", [])) or "não identificada"),
        "Provedor de DNS: " + (", ".join(r.get("dns_provider", [])) or "não identificado"),
        *summary,
    ])
    out.append(CollectedFact(
        target=domain, service="dns",
        title=f"DNS e hospedagem: {domain}",
        raw=raw,
        data={"severity_hint": "info", "source": "net_recon", "kind": "dns_info",
              "records": recs, "hosting": r.get("hosting", []),
              "dns_provider": r.get("dns_provider", []), "technologies": techs}))

    # 2) Camadas de proteção.
    waf = r.get("cdn_waf", {}).get("detected", [])
    email = r.get("email_security", {}).get("gateways", [])
    spfp = r.get("email_security", {}).get("spf_providers", [])
    dmon = r.get("security_tools", {}).get("dmarc_monitoring", [])
    posture = r.get("posture", {})

    layers: dict[str, str] = {}
    if waf:
        layers["WAF/CDN"] = ", ".join(waf)
    if email:
        layers["Gateway de e-mail"] = ", ".join(email)
    if posture.get("dmarc"):
        layers["DMARC"] = (f"p={posture.get('dmarc_policy') or '?'}"
                           + (" · " + ", ".join(dmon) if dmon else ""))
    if posture.get("spf"):
        layers["SPF"] = ", ".join(spfp) or "configurado"
    if posture.get("dnssec"):
        layers["DNSSEC"] = "habilitado"
    if posture.get("caa"):
        layers["CAA"] = "configurado"

    if layers:
        lines = [f"- {k}: {v}" for k, v in layers.items()]
        out.append(CollectedFact(
            target=domain, service="protection",
            title=f"Camadas de proteção detectadas ({len(layers)})",
            raw=("CAMADAS DE PROTEÇÃO (mérito da equipe de segurança do cliente):\n"
                 + "\n".join(lines)
                 + "\n\nORIENTAÇÃO AO PENTEST: a presença dessas camadas direciona a "
                 "abordagem — ex.: WAF/CDN exige técnicas de evasão/bypass e origem "
                 "real; gateway de e-mail reduz phishing direto; DMARC forte dificulta "
                 "spoofing do domínio."),
            data={"severity_hint": "info", "source": "net_recon",
                  "kind": "protection", "protection": True, "layers": layers,
                  "waf": waf, "email": email, "posture": posture,
                  "technologies": [f"Proteção: {k}" for k in layers]}))
    else:
        out.append(CollectedFact(
            target=domain, service="protection",
            title="Nenhuma camada de proteção externa detectada",
            raw=("Não foram detectadas camadas externas (WAF/CDN, gateway de e-mail, "
                 "DMARC/SPF). O alvo pode estar diretamente exposto.\n"
                 "ORIENTAÇÃO AO PENTEST: priorizar testes diretos à origem; verificar "
                 "exposição de serviços sem filtragem."),
            data={"severity_hint": "low", "source": "net_recon",
                  "kind": "protection_absent", "protection": False}))
    return out


class NetReconCollector:
    name = "net_recon"

    async def run(self, targets: list[str], ports: list[int] | None = None,
                  **kwargs) -> list[CollectedFact]:
        from app.netinfo import _host_only, network_lookup
        on_log = kwargs.get("on_log")
        cancel = kwargs.get("cancel_check")

        def _lg(m):
            if on_log:
                try:
                    on_log(m)
                except Exception:  # noqa: BLE001
                    pass

        out: list[CollectedFact] = []
        seen: set = set()
        for t in targets or []:
            if cancel and await cancel():
                break
            domain = _host_only(t)
            if not domain or "." not in domain or _is_ip(domain):
                continue  # recon de DNS é para domínios
            if domain in seen:
                continue
            seen.add(domain)
            _lg(f"  consultando DNS e proteções de {domain}")
            try:
                r = await network_lookup(domain)
            except Exception as exc:  # noqa: BLE001
                _lg(f"  ✕ falha em {domain}: {exc}")
                continue
            if r.get("error"):
                continue
            facts = _facts(domain, r)
            out.extend(facts)
            prot = next((f for f in facts if f.service == "protection"), None)
            if prot:
                _lg(f"  → {prot.title}")
        return out
