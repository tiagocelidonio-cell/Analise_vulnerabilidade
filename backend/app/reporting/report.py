"""Geracao de relatorio PDF no formato de pentest profissional.

Estrutura espelhada no modelo do cliente (Lozinsky): capa, Introducao
(contexto/objetivos/escopo/metodologia/classificacao/aviso legal), Resumo
executivo, Alvos identificados, Vulnerabilidades (resumo + detalhamento com
Descricao/Risco/Recomendacao/Evidencias/Classificacao) e Conclusao.

Configuravel via ReportOptions (ex.: nao incluir achados 'info', ocultar
evidencias, etc.). WeasyPrint importado de forma lazy.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from jinja2 import Template
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Engagement, Finding
from app.risk import build_matrix

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_PT = {"critical": "Crítico", "high": "Alto", "medium": "Médio",
           "low": "Baixo", "info": "Informativo"}
_SEV_COLOR = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#c2410c",
    "low": "#a16207", "info": "#334155",
}


@dataclass
class ReportOptions:
    min_sev: str = "info"          # menor severidade incluida
    include_methodology: bool = True
    include_matrix: bool = True
    include_targets: bool = True
    include_evidence: bool = True

    @classmethod
    def from_query(cls, min_sev="info", methodology=True, matrix=True,
                   targets=True, evidence=True) -> "ReportOptions":
        ms = min_sev if min_sev in _SEV_ORDER else "info"
        return cls(ms, bool(methodology), bool(matrix), bool(targets), bool(evidence))


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


_TEMPLATE = Template(
    """<!doctype html>
<html lang="pt-br"><head><meta charset="utf-8">
<style>
  @page { size: A4; margin: 2cm; @bottom-center { content: counter(page); color:#64748b; } }
  body { font-family: 'DejaVu Sans', sans-serif; color:#0f172a; font-size:11px; line-height:1.5; }
  h1 { font-size:26px; margin:0; color:#052e16; }
  h2 { font-size:17px; border-bottom:2px solid #0fdb2b; padding-bottom:4px; margin-top:26px; color:#052e16; }
  h3 { font-size:13px; margin:14px 0 4px; } h4 { font-size:12px; margin:10px 0 2px; color:#334155; }
  .cover { margin-top:22%; border-left:6px solid #0fdb2b; padding-left:16px; }
  .muted { color:#64748b; } .small { font-size:9px; }
  .pill { display:inline-block; padding:2px 8px; border-radius:10px; color:#fff; font-size:10px; font-weight:bold; }
  table { width:100%; border-collapse:collapse; margin-top:8px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid #e2e8f0; vertical-align:top; }
  th { background:#f1f5f9; font-size:10px; text-transform:uppercase; color:#475569; }
  .kpis { display:flex; gap:10px; margin-top:12px; }
  .kpi { flex:1; border:1px solid #e2e8f0; border-radius:8px; padding:10px; text-align:center; }
  .kpi .n { font-size:22px; font-weight:bold; } .kpi .l { font-size:10px; color:#64748b; }
  .finding { border:1px solid #e2e8f0; border-radius:8px; padding:12px; margin-top:12px; page-break-inside:avoid; }
  .finding h3 { border-left:5px solid #94a3b8; padding-left:8px; }
  .evi { background:#0f172a; color:#e2e8f0; font-family:'DejaVu Sans Mono',monospace;
       font-size:9px; padding:8px; border-radius:6px; white-space:pre-wrap; word-break:break-all; }
  .meta { color:#475569; font-size:10px; } .pb { page-break-before: always; }
  .rmatrix { border-collapse:collapse; margin:8px 0; width:auto; }
  .rmatrix td { width:40px; height:30px; text-align:center; color:#fff; font-weight:bold; border:2px solid #fff; }
  .rmatrix th { color:#64748b; font-size:9px; padding:3px; background:none; }
  .legal { background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:10px; font-size:10px; }
</style></head><body>

<div class="cover">
  <div class="muted">RELATÓRIO DE ANÁLISE DE VULNERABILIDADES / PENTEST</div>
  <h1>{{ eng.name }}</h1>
  <p class="muted">Cliente: <strong>{{ eng.client_name }}</strong><br>
     Escopo: {{ eng.scope|join(', ') if eng.scope else 'n/a' }}<br>
     Emitido em {{ generated_at }}<br>
     Autorizado por: {{ eng.authorized_by or 'n/a' }}</p>
  <p class="small muted">Documento CONFIDENCIAL — uso restrito ao cliente.</p>
</div>

{% if opt.include_methodology %}
<h2 class="pb">1. Introdução</h2>
<h3>Contexto</h3>
<p>Este relatório apresenta os resultados da análise de segurança conduzida sobre os ativos
   autorizados de <strong>{{ eng.client_name }}</strong>. O trabalho simula a atuação de um
   agente malicioso para identificar, de forma controlada e não-destrutiva, exposições e
   vulnerabilidades que possam comprometer a confidencialidade, integridade ou disponibilidade
   dos sistemas avaliados.</p>
<h3>Objetivos</h3>
<p>Mapear a superfície de ataque exposta, identificar vulnerabilidades e configurações
   inseguras, correlacioná-las a CVEs e evidências reprodutíveis, e fornecer recomendações
   priorizadas de remediação.</p>
<h3>Escopo das atividades</h3>
<p>Foram avaliados os seguintes alvos autorizados: <strong>{{ eng.scope|join(', ') if eng.scope else 'n/a' }}</strong>.
   As atividades foram conduzidas sem ataques de disponibilidade (DoS) e sem alteração de dados.</p>
<h3>Metodologia</h3>
<p>A avaliação seguiu um fluxo de reconhecimento (enumeração de subdomínios e ativos),
   varredura de portas e serviços (nmap), identificação de vulnerabilidades (nuclei e correlação
   de CVEs por versão de serviço), e validação não-destrutiva dos achados. Cada achado é
   acompanhado de evidência bruta coletada automaticamente.</p>
<h4>Classificação de severidade das vulnerabilidades</h4>
<table><thead><tr><th>Severidade</th><th>Faixa CVSS</th><th>Interpretação</th></tr></thead><tbody>
  <tr><td><span class="pill" style="background:#7f1d1d">CRÍTICO</span></td><td>9.0 – 10.0</td><td>Exploração trivial/impacto severo. Ação imediata.</td></tr>
  <tr><td><span class="pill" style="background:#b91c1c">ALTO</span></td><td>7.0 – 8.9</td><td>Risco elevado. Priorizar a correção.</td></tr>
  <tr><td><span class="pill" style="background:#c2410c">MÉDIO</span></td><td>4.0 – 6.9</td><td>Risco moderado. Corrigir no ciclo.</td></tr>
  <tr><td><span class="pill" style="background:#a16207">BAIXO</span></td><td>0.1 – 3.9</td><td>Risco baixo. Tratar conforme viabilidade.</td></tr>
  <tr><td><span class="pill" style="background:#334155">INFO</span></td><td>—</td><td>Informativo. Sem impacto direto.</td></tr>
</tbody></table>
<h3>Aviso legal</h3>
<div class="legal">As atividades foram executadas sob autorização formal do cliente, restritas ao
  escopo acima. As evidências são brutas, coletadas de forma não-destrutiva, e não foram geradas
  por IA. A reprodução deste documento é restrita ao cliente.</div>
{% endif %}

<h2 class="pb">2. Resumo executivo</h2>
<div class="kpis">
  {% for sev in sev_order %}
  <div class="kpi"><div class="n" style="color:{{ sev_color[sev] }}">{{ counts[sev] }}</div>
     <div class="l">{{ sev_pt[sev]|upper }}</div></div>
  {% endfor %}
</div>
<p>Foram considerados <strong>{{ total }}</strong> achado(s) em <strong>{{ hosts|length }}</strong>
   ativo(s){% if opt.min_sev != 'info' %} (filtrado: severidade mínima {{ sev_pt[opt.min_sev] }}){% endif %}.
   {{ exec_line }}</p>

{% if opt.include_matrix %}
<h3>Matriz de risco (probabilidade × impacto)</h3>
<p>Score médio de risco: <strong>{{ risk.avg_score }}</strong> &nbsp;|&nbsp;
   Com exploração ativa (KEV): <strong>{{ risk.kev_count }}</strong></p>
<table class="rmatrix">
  {% for row in risk_rows %}
  <tr><th>P{{ row.p }}</th>
    {% for c in row.cells %}<td style="background:{{ c.color }}">{{ c.n if c.n else '' }}</td>{% endfor %}
  </tr>
  {% endfor %}
  <tr><th></th>{% for i in [1,2,3,4,5] %}<th>I{{ i }}</th>{% endfor %}</tr>
</table>
<p class="muted small">Linhas = probabilidade (P1 baixa … P5 alta); colunas = impacto (I1 … I5).
   Número = achados na célula.</p>
{% endif %}

{% if opt.include_targets %}
<h2 class="pb">3. Alvos identificados e testados</h2>
<p>Relação de domínios, IPs e hosts avaliados / descobertos durante a enumeração:</p>
<table><thead><tr><th>Ativo</th><th>Maior risco</th><th>Achados</th></tr></thead><tbody>
{% for t in targets %}
<tr><td>{{ t.target }}</td>
    <td><span class="pill" style="background:{{ sev_color[t.risk] }}">{{ sev_pt[t.risk]|upper }}</span></td>
    <td>{{ t.findings }}</td></tr>
{% endfor %}
</tbody></table>
{% endif %}

<h2 class="pb">4. Vulnerabilidades encontradas</h2>
<h3>Resumo geral</h3>
<table><thead><tr><th>Sev</th><th>Alvo</th><th>Achado</th><th>CVSS</th>
  <th>EPSS</th><th>KEV</th></tr></thead><tbody>
{% for f in findings %}
<tr>
  <td><span class="pill" style="background:{{ sev_color[f.severity.value] }}">{{ sev_pt[f.severity.value]|upper }}</span></td>
  <td>{{ f.target }}{% if f.port %}:{{ f.port }}{% endif %}</td>
  <td>{{ f.title }}</td>
  <td>{{ '%.1f'|format(f.cvss) if f.cvss else '-' }}</td>
  <td>{{ '%.2f'|format(f.epss) if f.epss else '-' }}</td>
  <td>{{ 'SIM' if f.in_kev else '-' }}</td>
</tr>
{% endfor %}
</tbody></table>

<h3>Detalhamento das vulnerabilidades</h3>
{% for f in findings %}
<div class="finding">
  <h3 style="border-left-color:{{ sev_color[f.severity.value] }}">
    <span class="pill" style="background:{{ sev_color[f.severity.value] }}">{{ sev_pt[f.severity.value]|upper }}</span>
    {{ f.title }}</h3>
  <p class="meta">Alvo: {{ f.target }}{% if f.port %}:{{ f.port }}{% endif %}
     &nbsp;|&nbsp; Serviço: {{ f.service or '-' }}
     &nbsp;|&nbsp; Identificado em: {{ f.created_at.strftime('%d/%m/%Y') if f.created_at else '-' }}
     {% if f.cve_ids %}&nbsp;|&nbsp; CVEs: {{ f.cve_ids|join(', ') }}{% endif %}</p>
  {% if f.ai_assessment %}
    <h4>Descrição da vulnerabilidade</h4>
    <p>{{ f.ai_assessment.get('cve_description') or f.description or f.ai_assessment.get('risk_summary','') }}</p>
    <h4>Descrição do risco</h4>
    <p>{{ f.ai_assessment.get('risk_summary','') }}
       {% if f.ai_assessment.get('exploitability') %}<br><em>Explorabilidade:</em> {{ f.ai_assessment.get('exploitability') }}{% endif %}</p>
    <h4>Recomendação</h4>
    <p>{{ f.ai_assessment.get('recommendation','') }}
       {% if f.ai_assessment.get('remediation') %}<br>{{ f.ai_assessment.get('remediation') }}{% endif %}</p>
    {% if f.ai_assessment.get('references') %}
      <h4>Referências / patch</h4>
      <ul>{% for ref in f.ai_assessment.get('references') %}<li class="small">{{ ref }}</li>{% endfor %}</ul>
    {% endif %}
  {% endif %}
  {% if opt.include_evidence and f.evidences %}
    <h4>Evidências</h4>
    {% for ev in f.evidences %}
      <p class="meta small">{{ ev.kind }} · {{ ev.collected_at.strftime('%d/%m/%Y %H:%M UTC') }}</p>
      <div class="evi">{{ ev.content or ev.s3_key or '(sem conteúdo inline)' }}</div>
    {% endfor %}
  {% endif %}
  <h4>Classificação</h4>
  <p class="meta">Severidade: <strong>{{ sev_pt[f.severity.value] }}</strong>
     &nbsp;|&nbsp; CVSS: {{ '%.1f'|format(f.cvss) if f.cvss else '-' }}
     &nbsp;|&nbsp; EPSS: {{ '%.2f'|format(f.epss) if f.epss else '-' }}
     &nbsp;|&nbsp; KEV: {{ 'sim' if f.in_kev else 'não' }}
     &nbsp;|&nbsp; Confiança: {{ '%.0f'|format(f.confidence*100) }}%
     &nbsp;|&nbsp; Visto {{ f.times_seen or 1 }}×</p>
</div>
{% endfor %}
{% if not findings %}<p class="muted">Nenhum achado no filtro selecionado.</p>{% endif %}

<h2 class="pb">5. Conclusão e encerramento</h2>
<p>{{ exec_line }} Recomenda-se priorizar os achados de severidade crítica e alta, em especial os
   que possuem exploração ativa conhecida (KEV), seguidos pela correção dos itens de severidade
   média. A reavaliação após as correções (reteste) permite confirmar o fechamento das exposições.</p>

<p class="muted small" style="margin-top:24px;">
  Documento confidencial. Análise realizada sob autorização do cliente.
  Evidências são brutas e não foram geradas por IA.</p>
</body></html>"""
)


async def _load(session: AsyncSession, engagement_id: str, min_sev: str):
    eng = await session.get(Engagement, engagement_id)
    if eng is None:
        return None, []
    rows = await session.scalars(
        select(Finding)
        .where(Finding.engagement_id == engagement_id)
        .options(selectinload(Finding.evidences))
    )
    findings = list(rows)
    max_rank = _SEV_ORDER.index(min_sev)
    findings = [f for f in findings if _SEV_ORDER.index(f.severity.value) <= max_rank]
    findings.sort(key=lambda f: (_SEV_ORDER.index(f.severity.value), -(f.cvss or 0)))
    return eng, findings


def _exec_line(counts: dict) -> str:
    if counts["critical"] or counts["high"]:
        return ("Há achados de alta/crítica severidade que exigem ação imediata, "
                "priorizando itens com exploração ativa (KEV).")
    if counts["medium"]:
        return "Nenhum achado crítico; há itens de severidade média a tratar."
    return "Nenhum achado de alta severidade identificado neste ciclo."


async def render_html(
    session: AsyncSession, engagement_id: str, opt: ReportOptions | None = None,
) -> str | None:
    opt = opt or ReportOptions()
    eng, findings = await _load(session, engagement_id, opt.min_sev)
    if eng is None:
        return None
    counts = {s: sum(1 for f in findings if f.severity.value == s) for s in _SEV_ORDER}
    hosts = sorted({f.target for f in findings})

    # Alvos (ativo -> maior risco / nº achados), para a secao "Alvos".
    tmap: dict[str, dict] = {}
    for t in (eng.scope or []):
        tmap.setdefault(t, {"target": t, "risk": "info", "findings": 0})
    for f in findings:
        a = tmap.setdefault(f.target, {"target": f.target, "risk": "info", "findings": 0})
        a["findings"] += 1
        if _SEV_ORDER.index(f.severity.value) < _SEV_ORDER.index(a["risk"]):
            a["risk"] = f.severity.value
    targets = sorted(tmap.values(),
                     key=lambda x: (_SEV_ORDER.index(x["risk"]), -x["findings"]))

    risk = build_matrix(
        [{"id": f.id, "title": f.title, "target": f.target, "service": f.service,
          "severity": f.severity.value, "cvss": f.cvss, "epss": f.epss,
          "in_kev": f.in_kev} for f in findings]
    )
    matrix = risk["matrix"]
    risk_rows = [
        {"p": p, "cells": [
            {"n": matrix[p - 1][i - 1],
             "color": _score_color(p * i) if matrix[p - 1][i - 1] else "#e2e8f0"}
            for i in range(1, 6)]}
        for p in (5, 4, 3, 2, 1)
    ]

    return _TEMPLATE.render(
        eng=eng, findings=findings, counts=counts, total=len(findings),
        hosts=hosts, targets=targets, sev_order=_SEV_ORDER, sev_color=_SEV_COLOR,
        sev_pt=_SEV_PT, exec_line=_exec_line(counts), risk=risk, risk_rows=risk_rows,
        opt=opt,
        generated_at=datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"),
    )


def html_to_pdf(html: str) -> bytes:
    """Renderiza HTML -> PDF. Import lazy do WeasyPrint."""
    from weasyprint import HTML  # requer libs de sistema (ver Dockerfile)

    return HTML(string=html).write_pdf()
