"""Camada de IA isolada e provider-agnostica.

Contrato: a IA SO raciocina sobre fatos que os coletores ja provaram e
sobre o enriquecimento. Ela nunca inventa um fato, nunca "descobre" uma
porta. Entrada = fatos estruturados. Saida = avaliacao com confianca.

Sem ANTHROPIC_API_KEY, cai num stub deterministico para o sistema rodar
de ponta a ponta mesmo sem credencial.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from app.config import settings

SYSTEM_PROMPT = """Voce e um analista de seguranca ofensiva assistindo um pentester \
autorizado. Voce recebe FATOS ja coletados e enriquecidos sobre um alvo.

Regras inviolaveis:
- Raciocine APENAS sobre os fatos fornecidos. Nunca invente portas, versoes, \
CVEs ou respostas que nao estejam nos fatos.
- Se a evidencia for insuficiente, diga isso e baixe a confianca.
- Priorize por risco real: exposicao + explorabilidade (EPSS/KEV) + impacto.

Responda SOMENTE com um objeto JSON valido, sem texto ao redor, com as chaves:
  severity: "info"|"low"|"medium"|"high"|"critical"
  confidence: numero 0..1
  exploitability: string curta (como/por que seria exploravel, ou "n/a")
  risk_summary: string (1-2 frases para o relatorio executivo)
  recommendation: string curta (acao de remediacao)
"""


@dataclass
class AiAssessment:
    severity: str
    confidence: float
    exploitability: str
    risk_summary: str
    recommendation: str
    model: str = "stub"

    def to_dict(self) -> dict:
        return asdict(self)


def _stub_assessment(fact: dict, enrichment: dict) -> AiAssessment:
    """Heuristica deterministica usada quando nao ha chave de IA."""
    any_kev = enrichment.get("any_kev", False)
    max_epss = enrichment.get("max_epss", 0.0)
    service = (fact.get("service") or "").lower()
    hint = (fact.get("data") or {}).get("severity_hint")
    _order = ["info", "low", "medium", "high", "critical"]

    if any_kev:
        sev = "critical"
    elif max_epss >= 0.5:
        sev = "high"
    elif service in {"telnet", "ftp", "smb", "rdp", "redis", "mongodb"}:
        sev = "medium"
    else:
        sev = "info"

    # Respeita a dica do coletor (ex: header ausente, cert vencido) se for mais alta.
    if hint in _order and _order.index(hint) > _order.index(sev):
        sev = hint

    return AiAssessment(
        severity=sev,
        confidence=0.4,
        exploitability=(
            "Explorado ativamente (KEV)." if any_kev
            else f"EPSS max={max_epss:.2f}." if max_epss
            else "Sem CVE associado; exposicao de servico."
        ),
        risk_summary=(
            f"Servico {service or 'desconhecido'} exposto em "
            f"{fact.get('target')}:{fact.get('port')}."
        ),
        recommendation="Revisar exposicao, restringir acesso e atualizar o servico.",
        model="stub",
    )


class AiAnalyst:
    """Fachada unica para o resto do sistema. Trocar de provider mora aqui."""

    def __init__(self) -> None:
        self._client = None
        if settings.ai_enabled:
            from anthropic import AsyncAnthropic

            self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)

    async def assess(self, fact: dict, enrichment: dict) -> AiAssessment:
        if self._client is None:
            return _stub_assessment(fact, enrichment)

        payload = json.dumps(
            {"fact": fact, "enrichment": enrichment}, ensure_ascii=False
        )
        try:
            msg = await self._client.messages.create(
                model=settings.ai_model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": payload}],
            )
            text = "".join(
                block.text for block in msg.content if block.type == "text"
            )
            data = json.loads(text)
            return AiAssessment(
                severity=data.get("severity", "info"),
                confidence=float(data.get("confidence", 0.5)),
                exploitability=data.get("exploitability", "n/a"),
                risk_summary=data.get("risk_summary", ""),
                recommendation=data.get("recommendation", ""),
                model=settings.ai_model,
            )
        except Exception:
            # Falha de IA nunca derruba o pipeline: degrada pro stub.
            return _stub_assessment(fact, enrichment)


analyst = AiAnalyst()
