"""Interface de coletor. Todo coletor produz FATOS estruturados, nunca opinioes.

A IA so raciocina depois, sobre o que o coletor provou. Qualquer ferramenta
externa (masscan, nuclei, ...) pode virar um coletor implementando isto.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class CollectedFact:
    target: str
    port: int | None = None
    service: str | None = None
    title: str = ""
    raw: str = ""                       # evidencia bruta (banner, resposta http...)
    data: dict = field(default_factory=dict)


class Collector(Protocol):
    name: str

    async def run(self, targets: list[str], **kwargs) -> list[CollectedFact]:
        ...
