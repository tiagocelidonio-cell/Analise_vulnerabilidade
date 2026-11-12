"""Relatorio de benchmarking (Visao Geral) — inteligencia de vulnerabilidades.

ANONIMIZADO: nao expoe nomes de clientes. Mostra a matriz de risco comum,
as vulnerabilidades mais frequentes e sua prevalencia (%), para estudo e
orientacao em novos clientes.
"""
from __future__ import annotations

from datetime import datetime, timezone

from jinja2 import Template

from app.reporting.report import _SEV_COLOR, _score_color

_SEV = [("critical", "Crítico"), ("high", "Alto"), ("medium", "Médio"),
        ("low", "Baixo"), ("info", "Info")]

_TEMPLATE = Template(
    """<!doctype html><html lang="pt-br"><head><meta charset="utf-8"><style>
  @page { size: A4; margin: 2cm; @bottom-center { content: counter(page); color:#64748b; } }
  body { font-family:'DejaVu Sans',sans-serif; color:#0f172a; font-size:11px; }
  h1 { font-size:24px; margin:0; } h2 { font-size:15px; border-bottom:2px solid #e2e8f0;
       padding-bottom:4px; margin-top:26px; }
  .muted { color:#64748b; } .pill { color:#fff; padding:2px 8px; border-radius:10px;
       font-size:10px; font-weight:bold; }
  table { width:100%; border-collapse:collapse; margin-top:8px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid #e2e8f0; }
  th { background:#f1f5f9; font-size:10px; text-transform:uppercase; color:#475569; }
  .kpis { display:flex; gap:10px; margin-top:12px; }
  .kpi { flex:1; border:1px solid #e2e8f0; border-radius:8px; padding:10px; text-align:center; }
  .kpi .n { font-size:22px; font-weight:bold; } .kpi .l { font-size:10px; color:#64748b; }
  .rmatrix { border-collapse:collapse; margin:8px 0; }
  .rmatrix td { width:40px; height:30px; text-align:center; color:#fff; font-weight:bold;
       border:2px solid #fff; font-size:11px; }
  .rmatrix th { color:#64748b; font-size:9px; padding:3px; }
  .bar { background:#e2e8f0; border-radius:6px; height:12px; overflow:hidden; width:120px;
       display:inline-block; vertical-align:middle; }
  .barf { height:100%; }
</style></head><body>

<div class="muted">RELATÓRIO DE BENCHMARKING · INTELIGÊNCIA DE VULNERABILIDADES</div>
<h1>Visão geral da base</h1>
<p class="muted">Gerado em {{ now }} · Dados anonimizados (sem identificação de clientes).</p>

<div class="kpis">
  <div class="kpi"><div class="n">{{ d.total_clients }}</div><div class="l">CLIENTES</div></div>
  <div class="kpi"><div class="n">{{ d.total_findings }}</div><div class="l">ACHADOS</div></div>
  <div class="kpi"><div class="n" style="color:#b91c1c">{{ crit_high }}</div><div class="l">CRÍTICO+ALTO</div></div>
  <div class="kpi"><div class="n" style="color:#7f1d1d">{{ d.kev_count }}</div><div class="l">KEV</div></div>
  <div class="kpi"><div class="n">{{ d.avg_score }}</div><div class="l">SCORE MÉDIO</div></div>
</div>

<h2>Matriz de risco comum (probabilidade × impacto)</h2>
<table class="rmatrix">
  {% for row in risk_rows %}
  <tr><th>P{{ row.p }}</th>
    {% for c in row.cells %}<td style="background:{{ c.color }}">{{ c.n if c.n else '' }}</td>{% endfor %}
  </tr>{% endfor %}
  <tr><th></th>{% for i in [1,2,3,4,5] %}<th>I{{ i }}</th>{% endfor %}</tr>
</table>
<p class="muted">Linhas = probabilidade (P1..P5); colunas = impacto (I1..I5). Agregado de toda a base.</p>

<h2>Vulnerabilidades mais comuns</h2>
<table><thead><tr><th>Categoria</th><th>Clientes</th><th>Prevalência</th>
  <th>Ocorrências</th><th>Pior severidade</th></tr></thead><tbody>
{% for b in d.benchmark[:20] %}
<tr>
  <td>{{ b.category }}</td>
  <td>{{ b.clients }}</td>
  <td><span class="bar"><span class="barf" style="width:{{ b.prevalence }}%;
     background:{{ sev_color.get(b.worst_severity,'#334155') }}"></span></span> {{ b.prevalence }}%</td>
  <td>{{ b.occurrences }}</td>
  <td><span class="pill" style="background:{{ sev_color.get(b.worst_severity,'#334155') }}">{{ b.worst_severity|upper }}</span></td>
</tr>{% endfor %}
{% if not d.benchmark %}<tr><td colspan="5" class="muted">Sem dados ainda.</td></tr>{% endif %}
</tbody></table>

<h2>Severidade na base</h2>
<table><tbody>
{% for key, label in sev_labels %}
<tr><td style="width:120px">{{ label }}</td>
  <td><span class="bar"><span class="barf" style="width:{{ pct(key) }}%; background:{{ sev_color[key] }}"></span></span></td>
  <td style="width:50px; text-align:right"><b>{{ d.severity_dist.get(key, 0) }}</b></td></tr>
{% endfor %}
</tbody></table>

<h2>Distribuição de risco entre clientes (anonimizado)</h2>
<table><thead><tr><th>#</th><th>Cliente</th><th>Achados</th><th>Crít/Alto</th><th>Score médio</th></tr></thead><tbody>
{% for c in d.top_clients %}
<tr><td>{{ loop.index }}</td><td>Cliente {{ loop.index }}</td><td>{{ c.total }}</td>
  <td>{{ c.crit_high }}</td><td>{{ c.avg_score }}</td></tr>
{% endfor %}
{% if not d.top_clients %}<tr><td colspan="5" class="muted">Sem dados.</td></tr>{% endif %}
</tbody></table>

<h2>Insights</h2>
<ul>{% for i in d.insights %}<li>{{ i }}</li>{% endfor %}
{% if not d.insights %}<li class="muted">Sem insights ainda — rode varreduras.</li>{% endif %}</ul>

<p class="muted" style="margin-top:28px; font-size:9px;">
  Relatório de inteligência interna. Não identifica clientes. Uso restrito à equipe.</p>
</body></html>"""
)


def render_overview_html(d: dict) -> str:
    matrix = d.get("matrix") or [[0] * 5 for _ in range(5)]
    risk_rows = [
        {"p": p, "cells": [
            {"n": matrix[p - 1][i - 1],
             "color": _score_color(p * i) if matrix[p - 1][i - 1] else "#e2e8f0"}
            for i in range(1, 6)]}
        for p in (5, 4, 3, 2, 1)
    ]
    total = d.get("total_findings", 0) or 1
    crit_high = d.get("severity_dist", {}).get("critical", 0) + d.get("severity_dist", {}).get("high", 0)
    return _TEMPLATE.render(
        d=d, risk_rows=risk_rows, sev_color=_SEV_COLOR, sev_labels=_SEV,
        crit_high=crit_high,
        pct=lambda k: round(100 * d.get("severity_dist", {}).get(k, 0) / total),
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
