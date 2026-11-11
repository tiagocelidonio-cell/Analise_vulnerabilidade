"""Categorizacao de achados e benchmarking entre clientes.

Normaliza cada achado numa CATEGORIA (ex: "Header ausente", "Porta aberta: ssh",
"Arquivo sensivel exposto"). Com isso, agrega entre todos os clientes para
responder: quais vulnerabilidades sao mais comuns na base? Em quantos clientes
cada uma aparece? Serve de benchmarking e base de estudo.
"""
from __future__ import annotations

import re

_HEADER_RE = re.compile(r"^([a-z0-9-]+)\s+ausente", re.I)


def categorize(title: str, service: str | None, cve_ids: list | None) -> str:
    """Mapeia um achado para uma categoria normalizada."""
    t = (title or "").lower()
    svc = (service or "").lower()
    cves = cve_ids or []

    if "zone transfer" in t or "axfr" in t:
        return "Zone transfer (AXFR) permitido"
    if "[confirmado]" in t:
        return "Exposicao confirmada (validacao)"
    if "[dork]" in t:
        return "Lead OSINT (Google dork)"
    if "subdominio" in t:
        return "Subdominio exposto"
    if "certificado" in t or svc == "tls":
        return "Certificado TLS (vencido/invalido)"
    if "directory listing" in t or "index.of" in t or "listing" in t:
        return "Directory listing habilitado"
    if ".git" in t or ".env" in t or "backup" in t or "arquivo sensivel" in t:
        return "Arquivo/segredo sensivel exposto"
    m = _HEADER_RE.search(title or "")
    if m or "hsts" in t:
        hdr = m.group(1).upper() if m else "HSTS"
        return f"Security header ausente ({hdr})"
    if "sql injection" in t or "sqli" in t:
        return "SQL injection (indicio)"
    if "xss" in t:
        return "Cross-site scripting (indicio)"
    if "open redirect" in t:
        return "Open redirect"
    if "path traversal" in t or "lfi" in t:
        return "Path traversal / LFI"
    if cves:
        return f"Servico vulneravel (CVE): {svc or 'desconhecido'}"
    if "aberta" in t or svc in (
        "ssh", "ftp", "telnet", "rdp", "smb", "mysql", "postgres", "redis",
        "mongodb", "http", "https",
    ):
        return f"Servico/porta exposto: {svc or 'desconhecido'}"
    return "Outros"


def build_benchmark(items: list[dict]) -> list[dict]:
    """items: [{category, client, severity}]. Agrega por categoria.

    Retorna lista ordenada por numero de clientes afetados.
    """
    total_clients = len({it["client"] for it in items}) or 1
    agg: dict[str, dict] = {}
    sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    for it in items:
        cat = it["category"]
        a = agg.setdefault(cat, {"category": cat, "clients": set(),
                                 "occurrences": 0, "worst": "info"})
        a["clients"].add(it["client"])
        a["occurrences"] += 1
        if sev_rank.get(it["severity"], 1) > sev_rank.get(a["worst"], 1):
            a["worst"] = it["severity"]

    out = []
    for a in agg.values():
        n = len(a["clients"])
        out.append({
            "category": a["category"],
            "clients": n,
            "prevalence": round(100 * n / total_clients, 1),
            "occurrences": a["occurrences"],
            "worst_severity": a["worst"],
        })
    out.sort(key=lambda x: (x["clients"], x["occurrences"]), reverse=True)
    return out
