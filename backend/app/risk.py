"""Modelo de risco: probabilidade x impacto -> matriz 5x5.

Probabilidade (likelihood): quao provavel e a exploracao.
  deriva de KEV (exploracao ativa), EPSS (probabilidade estatistica) e
  exposicao do servico.
Impacto: quao grave se explorado.
  deriva de CVSS, severidade e sensibilidade do servico/achado.

Cada achado vira uma celula (prob, impacto) 1..5. Score = prob * impacto (1..25).
"""
from __future__ import annotations

_SEV_IMPACT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# servicos cujo comprometimento tende a alto impacto
_SENSITIVE_SERVICES = {
    "mssql": 5, "mysql": 5, "postgres": 5, "mongodb": 5, "redis": 5,
    "rdp": 4, "ssh": 4, "smb": 4, "ftp": 3, "telnet": 4, "elasticsearch": 4,
}

RISK_LEVELS = [
    (1, 4, "baixo"),
    (5, 9, "moderado"),
    (10, 14, "elevado"),
    (15, 19, "alto"),
    (20, 25, "critico"),
]


def probability(finding: dict) -> int:
    """1..5 — probabilidade de exploracao."""
    if finding.get("in_kev"):
        return 5
    epss = finding.get("epss") or 0.0
    if epss >= 0.5:
        return 5
    if epss >= 0.1:
        return 4
    if epss > 0:
        return 3
    # sem CVE: estima pela exposicao (achado existe = exposto)
    sev = finding.get("severity", "info")
    if sev in ("critical", "high"):
        return 3
    if sev == "medium":
        return 2
    return 1


def impact(finding: dict) -> int:
    """1..5 — impacto se explorado."""
    cvss = finding.get("cvss")
    base = 0
    if cvss is not None:
        if cvss >= 9:
            base = 5
        elif cvss >= 7:
            base = 4
        elif cvss >= 4:
            base = 3
        elif cvss > 0:
            base = 2
    sev_base = _SEV_IMPACT.get(finding.get("severity", "info"), 1)
    svc = (finding.get("service") or "").lower()
    svc_base = _SENSITIVE_SERVICES.get(svc, 0)
    return max(base, sev_base, svc_base, 1)


def level_for(score: int) -> str:
    for lo, hi, name in RISK_LEVELS:
        if lo <= score <= hi:
            return name
    return "critico"


def score_finding(finding: dict) -> dict:
    p = probability(finding)
    i = impact(finding)
    s = p * i
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "target": finding.get("target"),
        "severity": finding.get("severity"),
        "cve_ids": finding.get("cve_ids", []),
        "probability": p,
        "impact": i,
        "score": s,
        "level": level_for(s),
    }


def build_matrix(findings: list[dict]) -> dict:
    """Agrega os achados numa matriz 5x5 + rankings para o dashboard."""
    scored = [score_finding(f) for f in findings]

    # matriz[prob][impacto] = contagem  (prob e impacto de 1..5)
    matrix = [[0 for _ in range(5)] for _ in range(5)]
    for s in scored:
        matrix[s["probability"] - 1][s["impact"] - 1] += 1

    by_level: dict[str, int] = {}
    for s in scored:
        by_level[s["level"]] = by_level.get(s["level"], 0) + 1

    top = sorted(scored, key=lambda x: x["score"], reverse=True)[:10]
    total = len(scored)
    avg = round(sum(s["score"] for s in scored) / total, 1) if total else 0.0

    return {
        "matrix": matrix,            # linha = probabilidade (1..5), coluna = impacto (1..5)
        "scored": scored,
        "top_risks": top,
        "by_level": by_level,
        "total": total,
        "avg_score": avg,
        "kev_count": sum(1 for f in findings if f.get("in_kev")),
    }
