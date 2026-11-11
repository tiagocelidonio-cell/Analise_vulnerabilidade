"""Geracao de relatorio PDF (executivo + tecnico) a partir dos achados.

Usa WeasyPrint (HTML -> PDF). O import do WeasyPrint e lazy: a API sobe
mesmo sem as libs de sistema, e o endpoint retorna erro claro se faltarem.
"""
from __future__ import annotations

from datetime import datetime, timezone

from jinja2 import Template
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Engagement, Finding
from app.risk import build_matrix

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _score_color(score: int) -> str:
    if score >= 20:
        return "#7f1d1d"
    if score >= 15:
        return "#b91c1c"
    if score >= 10:
        return "#c2410c"
    if score >= 5:
        return "#a16207"
    return "#15803d"
_SEV_COLOR = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#c2410c",
    "low": "#a16207", "info": "#334155",
}

_TEMPLATE = Template(
    """<!doctype html>
<html lang="pt-br"><head><meta charset="utf-8">
<style>
  @page { size: A4; margin: 2cm; @bottom-center { content: counter(page); color:#64748b; } }
  body { font-family: 'DejaVu Sans', sans-serif; color:#0f172a; font-size:11px; }
  h1 { font-size:26px; margin:0; } h2 { font-size:16px; border-bottom:2px solid #e2e8f0;
       padding-bottom:4px; margin-top:28px; } h3 { font-size:13px; margin:14px 0 4px; }
  .cover { margin-top:30%; }
  .muted { color:#64748b; } .pill { display:inline-block; padding:2px 8px; border-radius:10px;
       color:#fff; font-size:10px; font-weight:bold; }
  table { width:100%; border-collapse:collapse; margin-top:8px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid #e2e8f0; vertical-align:top; }
  th { background:#f1f5f9; font-size:10px; text-transform:uppercase; color:#475569; }
  .kpis { display:flex; gap:10px; margin-top:12px; }
  .kpi { flex:1; border:1px solid #e2e8f0; border-radius:8px; padding:10px; text-align:center; }
  .kpi .n { font-size:22px; font-weight:bold; } .kpi .l { font-size:10px; color:#64748b; }
  .finding { border:1px solid #e2e8f0; border-radius:8px; padding:12px; margin-top:12px;
       page-break-inside:avoid; }
  .evi { background:#0f172a; color:#e2e8f0; font-family:'DejaVu Sans Mono',monospace;
       font-size:9px; padding:8px; border-radius:6px; white-space:pre-wrap; word-break:break-all; }
  .meta { color:#475569; font-size:10px; }
  .rmatrix { border-collapse:collapse; margin:8px 0; }
  .rmatrix td { width:40px; height:30px; text-align:center; color:#fff;
       font-weight:bold; border:2px solid #fff; font-size:11px; }
  .rmatrix th { color:#64748b; font-size:9px; padding:3px; }
</style></head><body>

<div class="cover">
  <div class="muted">RELATORIO DE ANALISE DE VULNERABILIDADES</div>
  <h1>{{ eng.name }}</h1>
  <p class="muted">Cliente: <strong>{{ eng.client_name }}</strong><br>
     Gerado em {{ generated_at }}<br>
     Autorizado por: {{ eng.authorized_by or 'n/a' }}</p>
</div>

<h2>Sumario executivo</h2>
<div class="kpis">
  {% for sev in sev_order %}
  <div class="kpi"><div class="n" style="color:{{ sev_color[sev] }}">{{ counts[sev] }}</div>
     <div class="l">{{ sev|upper }}</div></div>
  {% endfor %}
</div>
<p>Foram identificados <strong>{{ total }}</strong> achados em
   {{ hosts|length }} host(s). {{ exec_line }}</p>

<h2>Matriz de risco (probabilidade × impacto)</h2>
<p>Score médio de risco: <strong>{{ risk.avg_score }}</strong> &nbsp;|&nbsp;
   Explorados ativamente (KEV): <strong>{{ risk.kev_count }}</strong></p>
<table class="rmatrix">
  {% for row in risk_rows %}
  <tr><th>P{{ row.p }}</th>
    {% for c in row.cells %}
    <td style="background:{{ c.color }}">{{ c.n if c.n else '' }}</td>
    {% endfor %}
  </tr>
  {% endfor %}
  <tr><th></th>{% for i in [1,2,3,4,5] %}<th>I{{ i }}</th>{% endfor %}</tr>
</table>
<p class="muted">Linhas = probabilidade (P1 baixa … P5 alta); colunas = impacto
   (I1 baixo … I5 alto). Número = quantidade de achados na célula.</p>

<h3>Top 10 riscos priorizados</h3>
<table><thead><tr><th>#</th><th>Risco</th><th>Alvo</th><th>Prob</th>
  <th>Impacto</th><th>Score</th><th>Nível</th></tr></thead><tbody>
{% for r in top_risks %}
<tr><td>{{ loop.index }}</td><td>{{ r.title }}</td><td>{{ r.target }}</td>
  <td>{{ r.probability }}</td><td>{{ r.impact }}</td><td><strong>{{ r.score }}</strong></td>
  <td><span class="pill" style="background:{{ r.color }}">{{ r.level|upper }}</span></td></tr>
{% endfor %}
</tbody></table>

<h2>Achados por severidade</h2>
<table><thead><tr><th>Sev</th><th>Alvo</th><th>Achado</th><th>CVSS</th>
  <th>EPSS</th><th>KEV</th><th>Conf.</th></tr></thead><tbody>
{% for f in findings %}
<tr>
  <td><span class="pill" style="background:{{ sev_color[f.severity.value] }}">{{ f.severity.value|upper }}</span></td>
  <td>{{ f.target }}{% if f.port %}:{{ f.port }}{% endif %}</td>
  <td>{{ f.title }}</td>
  <td>{{ '%.1f'|format(f.cvss) if f.cvss else '-' }}</td>
  <td>{{ '%.2f'|format(f.epss) if f.epss else '-' }}</td>
  <td>{{ 'SIM' if f.in_kev else '-' }}</td>
  <td>{{ '%.0f'|format(f.confidence*100) }}%</td>
</tr>
{% endfor %}
</tbody></table>

<h2>Detalhamento tecnico</h2>
{% for f in findings %}
<div class="finding">
  <h3><span class="pill" style="background:{{ sev_color[f.severity.value] }}">{{ f.severity.value|upper }}</span>
      {{ f.title }}</h3>
  <p class="meta">Alvo: {{ f.target }}{% if f.port %}:{{ f.port }}{% endif %}
     &nbsp;|&nbsp; Servico: {{ f.service or '-' }}
     {% if f.cve_ids %}&nbsp;|&nbsp; CVEs: {{ f.cve_ids|join(', ') }}{% endif %}</p>
  {% if f.ai_assessment %}
    <p><strong>Risco:</strong> {{ f.ai_assessment.get('risk_summary','') }}</p>
    <p><strong>Explorabilidade:</strong> {{ f.ai_assessment.get('exploitability','') }}</p>
    <p><strong>Recomendacao:</strong> {{ f.ai_assessment.get('recommendation','') }}</p>
    <p class="meta">Avaliacao por: {{ f.ai_assessment.get('model','stub') }}</p>
  {% endif %}
  {% for ev in f.evidences %}
    <p class="meta">Evidencia ({{ ev.kind }}, {{ ev.collected_at.strftime('%Y-%m-%d %H:%M UTC') }}):</p>
    <div class="evi">{{ ev.content or ev.s3_key or '(sem conteudo inline)' }}</div>
  {% endfor %}
</div>
{% endfor %}

<p class="muted" style="margin-top:30px; font-size:9px;">
  Documento confidencial. Analise realizada sob autorizacao do cliente.
  Evidencias sao brutas e nao foram geradas por IA.</p>
</body></html>"""
)


async def _load(session: AsyncSession, engagement_id: str):
    eng = await session.get(Engagement, engagement_id)
    if eng is None:
        return None, []
    rows = await session.scalars(
        select(Finding)
        .where(Finding.engagement_id == engagement_id)
        .options(selectinload(Finding.evidences))
    )
    findings = list(rows)
    findings.sort(key=lambda f: (_SEV_ORDER.index(f.severity.value), -(f.cvss or 0)))
    return eng, findings


def _exec_line(counts: dict) -> str:
    if counts["critical"] or counts["high"]:
        return ("Ha achados de alta/critica severidade que exigem acao imediata, "
                "priorizando itens com exploracao ativa (KEV).")
    if counts["medium"]:
        return "Nenhum achado critico; ha itens de severidade media a tratar."
    return "Nenhum achado de alta severidade identificado neste ciclo."


async def render_html(session: AsyncSession, engagement_id: str) -> str | None:
    eng, findings = await _load(session, engagement_id)
    if eng is None:
        return None
    counts = {s: sum(1 for f in findings if f.severity.value == s) for s in _SEV_ORDER}
    hosts = sorted({f.target for f in findings})

    # Dados de risco (matriz 5x5 + top riscos) para o relatorio executivo.
    risk = build_matrix(
        [
            {"id": f.id, "title": f.title, "target": f.target, "service": f.service,
             "severity": f.severity.value, "cvss": f.cvss, "epss": f.epss,
             "in_kev": f.in_kev}
            for f in findings
        ]
    )
    matrix = risk["matrix"]
    risk_rows = [
        {"p": p, "cells": [
            {"n": matrix[p - 1][i - 1],
             "color": _score_color(p * i) if matrix[p - 1][i - 1] else "#e2e8f0"}
            for i in range(1, 6)
        ]}
        for p in (5, 4, 3, 2, 1)
    ]
    top_risks = [dict(r, color=_score_color(r["score"])) for r in risk["top_risks"]]

    return _TEMPLATE.render(
        eng=eng, findings=findings, counts=counts, total=len(findings),
        hosts=hosts, sev_order=_SEV_ORDER, sev_color=_SEV_COLOR,
        exec_line=_exec_line(counts), risk=risk, risk_rows=risk_rows,
        top_risks=top_risks,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def html_to_pdf(html: str) -> bytes:
    """Renderiza HTML -> PDF. Import lazy do WeasyPrint."""
    from weasyprint import HTML  # requer libs de sistema (ver Dockerfile)

    return HTML(string=html).write_pdf()
